"""Invented report mutation tests and real owned TLS/H3 server/client tests.

The clients here are Python/OpenSSL and aioquic, never native-browser acceptance.
"""
import asyncio
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path
import socket
import ssl
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fingerprint_protocols as tls
import fingerprint_transport_audit as transport
import fingerprint_transport_lifecycle_audit as lifecycle
import fingerprint_quic_audit as quic
from test_fingerprint_protocols import hello, transport_report


def lifecycle_report():
    result = {'errors': [], 'runs': [], 'connections': [], 'client_hellos': []}
    for context in range(2):
        connections = []
        for offset in range(2):
            connection_id = 1 + context * 2 + offset
            connection = {'id': connection_id, 'tls': 'TLSv1.3', 'alpn': 'h2',
                'session_reused': bool(offset), 'settings': [[[1, 65536], [4, 6291456]]], 'requests': []}
            connections.append(connection)
            h = tls.parse_client_hello(hello())
            h['connection_id'] = connection_id
            if offset:
                h['extensions'].append(41)
            result['client_hellos'].append(h)
        phases = []
        for i, phase in enumerate(lifecycle.PHASES):
            c = connections[i > 2]
            path = f'/echo?context={context}&phase={phase}' + ('&close=1' if phase == 'goaway' else '')
            headers = [[':method','GET'], [':authority','localhost:1234'], [':scheme','https'], [':path',path]]
            request = {'stream': 1 + 2 * len(c['requests']), 'headers': headers, 'pseudo_order': [k for k, _ in headers]}
            c['requests'].append(request)
            if phase == 'goaway':
                c['goaway_stream'] = request['stream']
            phases.append({'phase': phase, 'wire': {'connection_id': c['id'], 'headers': dict(headers)}})
        identity = deepcopy(transport_report()['observations'][0])
        headers = [[':method','GET'], [':authority','localhost:1234'], [':scheme','https'], [':path','/echo'],
                   *identity['wire']['headers'].items()]
        c = connections[-1]
        c['requests'].append({'stream': 1 + 2 * len(c['requests']), 'headers': headers,
                             'pseudo_order': [k for k, _ in headers[:4]]})
        identity['wire'] = {'connection_id': c['id'], 'headers': dict(headers)}
        result['runs'].append({'context': context, 'phases': phases, 'identity': identity})
        result['connections'].extend(connections)
    return result


def test_lifecycle_raw_fixture_has_separate_full_and_resumed_comparisons():
    errors, comparisons = lifecycle.assess(lifecycle_report())
    assert errors == []
    assert [c['kind'] for c in comparisons] == ['full', 'resumed']
    assert all(c['status'] == 'observed_match' for c in comparisons)


@pytest.mark.parametrize('status', [200, 503, None])
def test_lifecycle_collector_binds_initial_phase_to_navigation(monkeypatch, tmp_path, status):
    fixture = lifecycle_report()
    rows, navigations, closed = iter(fixture['runs']), [], []
    origin = 'https://localhost:1234'

    def new_context(**kwargs):
        row = next(rows)

        def goto(url, **kwargs):
            navigations.append(url)
            assert url == origin + f'/echo?context={row["context"]}&phase=initial'
            if status is None:
                return None
            return SimpleNamespace(ok=status == 200, json=lambda: deepcopy(row['phases'][0]['wire']))

        def evaluate(script, argument):
            if script == lifecycle.launch.bounded(lifecycle.PROBE):
                assert argument == row['context']
                assert "'initial'" not in lifecycle.PROBE
                return deepcopy(row['phases'][1:])
            assert script == lifecycle.launch.bounded(lifecycle.IDENTITY) and argument is None
            return deepcopy(row['identity'])

        page = SimpleNamespace(goto=goto, evaluate=evaluate)
        return SimpleNamespace(new_page=lambda: page, close=lambda: closed.append(row['context']))

    instance = SimpleNamespace(version='152.0.7977.82', new_context=new_context,
                               close=lambda: closed.append('browser'))
    pw = SimpleNamespace(chromium=SimpleNamespace(launch=lambda **kwargs: instance))
    server = SimpleNamespace(spki='fixture', hellos=fixture['client_hellos'],
                             connections=fixture['connections'], handshake_errors=[])
    monkeypatch.setitem(sys.modules, 'playwright.sync_api', SimpleNamespace(sync_playwright=lambda: nullcontext(pw)))
    monkeypatch.setattr(lifecycle, 'endpoint', lambda *args, **kwargs: nullcontext((server, origin)))
    monkeypatch.setattr(lifecycle.launch.pool, 'file_hash', lambda _: 'a' * 64)
    report = lifecycle.run(tmp_path / 'browser')
    if status == 200:
        assert report['errors'] == [] and report['status'] == 'passed'
        assert report['runs'] == fixture['runs']
        assert len(navigations) == 2 and closed == [0, 1, 'browser']
    else:
        assert report['status'] == 'failed' and report['errors']
        assert report['runs'] == [] and closed == [0, 'browser']


def test_lifecycle_unbound_navigation_cannot_replace_resumed_initial_phase():
    report = lifecycle_report()
    navigation = deepcopy(report['connections'][0])
    navigation['id'] = 5
    navigation['requests'] = [deepcopy(navigation['requests'][0])]
    navigation['requests'][0]['headers'][3][1] = '/'
    navigation.pop('goaway_stream')
    report['connections'].append(navigation)
    report['client_hellos'].append({**deepcopy(report['client_hellos'][0]), 'connection_id': 5})
    report['connections'][0]['session_reused'] = True
    report['client_hellos'][0]['extensions'].append(41)
    errors, comparisons = lifecycle.assess(report)
    assert 'full: negotiated TLS13/H2 session state mismatch' in errors
    assert 'full: PSK offer does not match session state' in errors
    assert 'full: TLS profile changed across browser contexts' in errors
    assert comparisons[0]['status'] == 'mismatch'


@pytest.mark.parametrize('mutate', [
    lambda r: r['connections'][1].update(session_reused=False),
    lambda r: r['connections'][0].update(session_reused=True),
    lambda r: r['connections'][1].update(tls='TLSv1.2'),
    lambda r: r['connections'][1].update(settings=[]),
    lambda r: r['connections'][1].update(settings=[[[1, 1]]]),
    lambda r: r['connections'][0].update(goaway_stream=999),
    lambda r: r['client_hellos'].pop(),
    lambda r: r['client_hellos'][1]['extensions'].remove(41),
    lambda r: r['client_hellos'][0]['extensions'].append(41),
    lambda r: r['client_hellos'][2]['ciphers'].reverse(),
    lambda r: r['client_hellos'][3]['ciphers'].reverse(),
    lambda r: r['client_hellos'][0].update(connection_id=9),
    lambda r: r['runs'].pop(),
    lambda r: r['runs'][0]['phases'].pop(),
    lambda r: r['runs'][0]['phases'][1]['wire'].update(connection_id=2),
    lambda r: r['runs'][0]['phases'][1]['wire']['headers'].update({':path':'/unobserved'}),
    lambda r: r['connections'][0]['requests'][0]['pseudo_order'].reverse(),
    lambda r: r['connections'][0]['requests'][1].update(stream=1),
    lambda r: r['connections'][0].update(settings=[[[1, True]]]),
    lambda r: r['runs'][0].update(context=False),
    lambda r: r['runs'][0]['identity']['wire'].update(connection_id=1),
    lambda r: r['runs'][0]['identity']['wire']['headers'].update({'sec-ch-ua-arch':'"arm"'}),
])
def test_lifecycle_forged_pass_does_not_replace_wire_evidence(mutate):
    report = lifecycle_report()
    report['status'] = 'passed'
    mutate(report)
    assert lifecycle.assess(report)[0]


def test_owned_tls13_tickets_goaway_and_connection_binding(tmp_path):
    pytest.importorskip('h2')
    pytest.importorskip('cryptography')
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, StreamEnded
    if not ssl.HAS_TLSv1_3:
        pytest.skip('local OpenSSL TLS1.3 required')
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE  # Owned local Python fixture, not browser launch policy.
    client.set_alpn_protocols(['h2'])
    with transport.endpoint(tmp_path, tickets=True) as (server, origin):
        address = urlsplit(origin)
        def connect(session=None):
            raw = socket.create_connection((address.hostname, address.port), timeout=5)
            connection = client.wrap_socket(raw, server_hostname=address.hostname, session=session)
            h2 = H2Connection(H2Configuration(client_side=True, header_encoding='utf-8'))
            h2.initiate_connection()
            connection.sendall(h2.data_to_send())
            return connection, h2
        def request(connection, h2, path):
            stream = h2.get_next_available_stream_id()
            h2.send_headers(stream, [(':method','GET'), (':authority',address.netloc),
                                    (':scheme','https'), (':path',path)], end_stream=True)
            connection.sendall(h2.data_to_send())
            body = bytearray()
            for _ in range(64):
                data = connection.recv(65536)
                assert data
                done = False
                for event in h2.receive_data(data):
                    if isinstance(event, DataReceived) and event.stream_id == stream:
                        body.extend(event.data)
                    if isinstance(event, StreamEnded) and event.stream_id == stream:
                        done = True
                if done:
                    return json.loads(body)
                connection.sendall(h2.data_to_send())
            raise AssertionError('unbounded fixture response')
        first, h2 = connect()
        with first:
            a = request(first, h2, '/echo?phase=initial')
            b = request(first, h2, '/echo?phase=reuse')
            closed = request(first, h2, '/echo?close=1')
            ticket = first.session
            assert ticket.has_ticket and not first.session_reused
        resumed, h2 = connect(ticket)
        with resumed:
            c = request(resumed, h2, '/echo?phase=resumed')
            assert resumed.session_reused
            assert request(resumed, h2, '/echo?phase=reuse_after')['connection_id'] == c['connection_id']
        assert a['connection_id'] == b['connection_id'] == closed['connection_id'] != c['connection_id']
    by_id = {c['id']: c for c in server.connections}
    assert by_id[a['connection_id']]['goaway_stream'] == 5
    assert by_id[c['connection_id']]['session_reused'] is True
    for wire, resumed in ((a, False), (c, True)):
        hellos = [h for h in server.hellos if h['connection_id'] == wire['connection_id']]
        assert len(hellos) == 1 and (41 in hellos[0]['extensions']) is resumed
    assert not server.handshake_errors


def encode_varint(value):
    for length, tag in ((1,0), (2,1), (4,2), (8,3)):
        if value < 1 << (length * 8 - 2):
            return ((tag << (length * 8 - 2)) | value).to_bytes(length, 'big')
    raise ValueError(value)


def transport_parameters():
    values = {1: encode_varint(10000), 3: encode_varint(1350),
              **{key: encode_varint(65536) for key in range(4, 10)},
              12: b'', 15: b'fake-cid', 27: b'grease', 12345: b'unknown fixture'}
    return b''.join(encode_varint(k) + encode_varint(len(v)) + v for k, v in values.items())


def quic_report():
    report = {'errors': [], 'route': 'forced-owned-loopback', 'runs': [], 'connections': []}
    for context in range(2):
        identity = deepcopy(transport_report()['observations'][0])
        c = {'id': str(context) * 64, 'handshake': {'alpn':'h3', 'version':1, 'session_resumed':False,
             'early_data_accepted':False}, 'long_header_versions':[1], 'requests':[],
             'settings': [[1,65536],[7,100],[33,42]],
             'transport_parameters': quic.parse_transport_parameters(transport_parameters())}
        reuse = []
        for index in range(3):
            headers = [[':method','GET'], [':authority','localhost:1234'], [':scheme','https'],
                       [':path','/echo' + (f'?reuse={index - 1}' if index else '')]]
            if not index:
                headers.extend(identity['wire']['headers'].items())
            c['requests'].append({'stream': index * 4, 'headers': headers, 'pseudo_order': [k for k, _ in headers[:4]]})
            wire = {'headers':dict(headers), 'connection_id':c['id']}
            if index:
                reuse.append(wire)
            else:
                identity['wire'] = wire
        report['runs'].append({'context':context, 'identity':identity, 'reuse':reuse, 'navigation_protocol':'h3'})
        report['connections'].append(c)
    return report


def test_quic_parameters_decode_unknowns_without_cid_or_token_bytes():
    value = quic.parse_transport_parameters(transport_parameters())
    rows = {row['id']:row for row in value['parameters']}
    assert rows[15] == {'id':15, 'name':'initial_source_connection_id', 'length':8, 'opaque':True}
    assert rows[4]['value'] == 65536 and len(rows[12345]['value_sha256']) == 64
    other = deepcopy(value)
    other['parameters'].reverse()
    grease = next(r for r in other['parameters'] if r['id'] == 27)
    grease.update(id=27 + 31 * 72, length=23)
    assert quic.canonical_parameters(value) == quic.canonical_parameters(other)
    assert not quic.assess(quic_report())


def quic_version_report(versions):
    report = quic_report()
    for c, values in zip(report['connections'], versions):
        payload = b''.join(v.to_bytes(4, 'big') for v in values)
        block = transport_parameters() + encode_varint(17) + encode_varint(len(payload)) + payload
        c['transport_parameters'] = quic.parse_transport_parameters(block)
    return report


def test_quic_reserved_version_insertion_is_not_a_profile_change():
    report = quic_version_report(([1, 1, 1783253706], [1, 3129658042, 1]))
    assert quic.assess(report) == []
    assert quic.assess(quic_version_report(([1, 1, 2, 0x1a2a3a4a], [1, 0xfaeada0a, 1, 2]))) == []


@pytest.mark.parametrize('versions', [
    [2, 1, 2, 0x1a2a3a4a],
    [1, 2, 1, 0x1a2a3a4a],
    [1, 1, 3, 0x1a2a3a4a],
    [1, 1, 2],
    [1, 1, 2, 0x1a2a3a4a, 0xfaeada0a],
    [1, 1, 2, 0x1a2a3a4b],
    [1, 1, 1, 2, 0x1a2a3a4a],
])
def test_quic_real_version_order_and_grease_count_differences_fail(versions):
    report = quic_version_report(([1, 1, 2, 0x1a2a3a4a], versions))
    assert 'QUIC transport parameters changed across contexts or were not observed' in quic.assess(report)


def test_quic_chosen_version_is_not_grease_normalized():
    report = quic_version_report(([0x1a2a3a4a, 1], [0xfaeada0a, 1]))
    assert quic.assess(report)


@pytest.mark.parametrize('mutate', [
    lambda row: row.update(versions=[]),
    lambda row: row.update(versions=[1, True, 0x0a0a0a0a]),
    lambda row: row.update(versions=[1, 1, 2**32]),
    lambda row: row.update(length=8),
    lambda row: row.pop('versions'),
    lambda row: row.update(value_sha256='a' * 64, versions=None),
])
def test_quic_malformed_version_information_fails(mutate):
    report = quic_version_report(([1, 1, 0x0a0a0a0a], [1, 1, 0x0a0a0a0a]))
    mutate(report['connections'][0]['transport_parameters']['parameters'][-1])
    assert quic.assess(report)


@pytest.mark.parametrize('data', [b'', b'\x40', b'\x04\x01', b'\x04\x02\x40', b'\x0c\x01x',
    b'\x04\x02\0\0', b'\x11\x01x', b'\x0c\0\x0c\0', b'x' * 65537])
def test_malformed_quic_parameter_blocks_fail(data):
    with pytest.raises(ValueError):
        quic.parse_transport_parameters(data)


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(route='external'),
    lambda r: r['runs'].pop(),
    lambda r: r['runs'][0].update(navigation_protocol='h2'),
    lambda r: r['runs'][0]['reuse'].pop(),
    lambda r: r['runs'][0]['reuse'][0].update(connection_id='missing'),
    lambda r: r['runs'][0]['reuse'].__setitem__(1, deepcopy(r['runs'][0]['reuse'][0])),
    lambda r: r['connections'][0]['requests'][1].update(stream=0),
    lambda r: r['runs'][0].update(context=False),
    lambda r: r['connections'][0]['handshake'].update(version=True),
    lambda r: r['connections'][0]['handshake'].update(version=2),
    lambda r: r['connections'][0]['handshake'].update(session_resumed=True),
    lambda r: r['connections'][0].update(long_header_versions=[]),
    lambda r: r['connections'][0].update(settings=[]),
    lambda r: r['connections'][0]['settings'].append([1,1]),
    lambda r: r['connections'][0]['settings'][0].__setitem__(1, 9),
    lambda r: r['connections'][0]['requests'][0]['pseudo_order'].reverse(),
    lambda r: r['connections'][0].pop('transport_parameters'),
    lambda r: r['connections'][0]['transport_parameters'].update(parameters=[]),
    lambda r: r['connections'][0]['transport_parameters']['parameters'].pop(),
    lambda r: r['connections'][0]['transport_parameters']['parameters'][-1].update(value_sha256='a' * 64),
    lambda r: r['connections'][0]['transport_parameters']['parameters'][2].update(value=9),
    lambda r: r['runs'][0]['identity']['wire']['headers'].update({'sec-ch-ua-arch':'"arm"'}),
])
def test_quic_forged_summary_cannot_hide_missing_negotiation_or_wire(mutate):
    report = quic_report()
    report['status'] = 'passed'
    mutate(report)
    assert quic.assess(report)


def test_owned_h3_server_observes_real_client_settings_parameters_and_reuse(tmp_path):
    pytest.importorskip('aioquic')
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ProtocolNegotiated
    class Client(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http, self.pending, self.bodies = None, {}, {}
        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated):
                self.http = H3Connection(self._quic)
            if self.http:
                for item in self.http.handle_event(event):
                    if isinstance(item, DataReceived):
                        self.bodies[item.stream_id].extend(item.data)
                        if item.stream_ended:
                            self.pending.pop(item.stream_id).set_result(json.loads(self.bodies.pop(item.stream_id)))
        async def request(self, authority, path):
            stream = self._quic.get_next_available_stream_id()
            result = asyncio.get_running_loop().create_future()
            self.pending[stream], self.bodies[stream] = result, bytearray()
            self.http.send_headers(stream, [(b':method',b'GET'), (b':authority',authority.encode()),
                (b':scheme',b'https'), (b':path',path.encode())], end_stream=True)
            self.transmit()
            return await asyncio.wait_for(result, timeout=5)
    with quic.endpoint(tmp_path) as (server, origin):
        address = urlsplit(origin)
        async def collect():
            out = []
            for _ in range(2):
                config = QuicConfiguration(is_client=True, alpn_protocols=['h3'], verify_mode=ssl.CERT_NONE)
                async with connect(address.hostname, address.port, configuration=config, create_protocol=Client) as client:
                    a = await client.request(address.netloc, '/echo?phase=initial')
                    b = await client.request(address.netloc, '/echo?phase=reuse')
                    assert a['connection_id'] == b['connection_id']
                    out.append(a['connection_id'])
            return out
        ids = asyncio.run(collect())
    assert len(set(ids)) == 2 and not server['errors']
    assert len(server['connections']) == 2
    profiles = []
    for c in server['connections']:
        assert c['id'] in ids and len(c['requests']) == 2
        assert c['handshake'] == {'alpn':'h3','version':1,'session_resumed':False,'early_data_accepted':False}
        assert 1 in c['long_header_versions']
        assert quic.canonical_settings(c['settings'])
        profiles.append(quic.canonical_parameters(c['transport_parameters']))
    assert profiles[0] == profiles[1]


@pytest.mark.parametrize('report', [None, {}, [], {'status':'passed'}, {'connections':None}])
def test_missing_transport_reports_fail(report):
    assert lifecycle.assess(report)[0]
    assert quic.assess(report)


def test_release_gate_rechecks_tls_resumption_and_quic_observations():
    import fingerprint_acceptance as acceptance
    for name, report in (('transport_lifecycle', lifecycle_report()), ('quic', quic_report())):
        report.update(status='passed', browser_sha256='a' * 64, browser_version='152.0.7977.82')
        assert acceptance.assess_suite(name, report, 'a' * 64, '152.0.7977.82') == ([], [])
        report['connections'].clear()
        assert acceptance.assess_suite(name, report, 'a' * 64, '152.0.7977.82')[0]

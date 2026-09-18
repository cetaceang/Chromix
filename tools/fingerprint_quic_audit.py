#!/usr/bin/env python3
"""Real QUIC/H3 observations on an explicitly forced, owned loopback origin.

This diagnostic does not qualify Alt-Svc discovery, a proxy, external UDP routes,
connection migration, 0-RTT or a physical network. No ticket/key bytes are saved.
"""
from __future__ import annotations
import argparse
import asyncio
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import queue
import re
import tempfile
import threading

from fingerprint_transport_audit import certificate, HINTS, IDENTITY, launch, header_errors

DRIVER_VERSION = '1.2.0'
INTEGER_PARAMETERS = {
    1: 'max_idle_timeout', 3: 'max_udp_payload_size', 4: 'initial_max_data',
    5: 'initial_max_stream_data_bidi_local', 6: 'initial_max_stream_data_bidi_remote',
    7: 'initial_max_stream_data_uni', 8: 'initial_max_streams_bidi', 9: 'initial_max_streams_uni',
    10: 'ack_delay_exponent', 11: 'max_ack_delay', 14: 'active_connection_id_limit',
    32: 'max_datagram_frame_size',
}
OPAQUE_PARAMETERS = {0: 'original_destination_connection_id', 2: 'stateless_reset_token',
                     13: 'preferred_address', 15: 'initial_source_connection_id',
                     16: 'retry_source_connection_id'}


def varint(data, offset):
    if offset >= len(data):
        raise ValueError('truncated QUIC variable integer')
    width = 1 << (data[offset] >> 6)
    end = offset + width
    if end > len(data):
        raise ValueError('truncated QUIC variable integer')
    return int.from_bytes(data[offset:end], 'big') & ((1 << (width * 8 - 2)) - 1), end


def parse_transport_parameters(data):
    """Decode every received parameter; retain unknown hashes, never CID/token bytes."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= 65536:
        raise ValueError('invalid QUIC transport parameter block size')
    offset, seen, result = 0, set(), []
    while offset < len(data):
        key, offset = varint(data, offset)
        length, offset = varint(data, offset)
        if key in seen or len(seen) >= 256 or offset + length > len(data):
            raise ValueError('duplicate, oversized or truncated QUIC parameter')
        seen.add(key)
        payload = data[offset:offset + length]
        offset += length
        entry = {'id': key, 'length': length}
        if key in INTEGER_PARAMETERS:
            value, end = varint(payload, 0)
            if end != length:
                raise ValueError('invalid QUIC integer parameter length')
            entry.update(name=INTEGER_PARAMETERS[key], value=value)
        elif key == 12:
            if length:
                raise ValueError('disable_active_migration must have an empty value')
            entry.update(name='disable_active_migration', value=True)
        elif key in OPAQUE_PARAMETERS:
            entry.update(name=OPAQUE_PARAMETERS[key], opaque=True)
        elif key == 17:
            if length < 4 or length % 4:
                raise ValueError('invalid QUIC version_information')
            entry.update(name='version_information', versions=[int.from_bytes(payload[i:i + 4], 'big')
                                                               for i in range(0, length, 4)])
        elif key >= 27 and (key - 27) % 31 == 0:
            entry['grease'] = True
        else:
            entry['value_sha256'] = hashlib.sha256(payload).hexdigest()
        result.append(entry)
    return {'message_sha256': hashlib.sha256(data).hexdigest(), 'parameters': result}


def canonical_parameters(observed):
    rows, seen, result = observed['parameters'], set(), []
    if not isinstance(rows, list) or not rows or len(rows) > 256:
        raise ValueError('missing QUIC parameters')
    for row in rows:
        key, length = row['id'], row['length']
        if (type(key) is not int or not 0 <= key < 2**62 or key in seen or
                type(length) is not int or not 0 <= length <= 65536):
            raise ValueError('invalid QUIC parameter evidence')
        seen.add(key)
        if key >= 27 and (key - 27) % 31 == 0:
            result.append(['grease'])
        elif key in OPAQUE_PARAMETERS:
            if row.get('opaque') is not True:
                raise ValueError('missing opaque parameter marker')
            result.append([key, length])
        elif key == 17:
            versions = row['versions']
            if (not isinstance(versions, list) or not versions or length != 4 * len(versions) or
                    any(type(v) is not int or not 0 <= v < 2**32 for v in versions)):
                raise ValueError('invalid QUIC version information evidence')
            # Keep the chosen version and real-version order; GREASE insertion varies.
            available = [v for v in versions[1:] if v & 0x0f0f0f0f != 0x0a0a0a0a]
            grease_count = len(versions) - 1 - len(available)
            result.append([key, [versions[0], *available, *([0x0a0a0a0a] * grease_count)]])
        elif key in INTEGER_PARAMETERS:
            value = row['value']
            if type(value) is not int or not 0 <= value < 2**62 or length not in (1, 2, 4, 8):
                raise ValueError('invalid QUIC integer parameter evidence')
            result.append([key, value])
        elif key == 12:
            if row.get('value') is not True or length != 0:
                raise ValueError('invalid QUIC migration flag evidence')
            result.append([key, True])
        else:
            digest = row.get('value_sha256')
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('unknown QUIC parameter lacks a payload digest')
            result.append([key, length, digest])
    if not {4, 5, 6, 7, 8, 9, 15} <= seen:
        raise ValueError('missing required browser flow-control/connection evidence')
    return sorted(result, key=lambda row: str(row[0]))


def canonical_settings(settings):
    if not isinstance(settings, list) or not settings or len(settings) > 256:
        raise ValueError('missing HTTP3 SETTINGS')
    result, seen = [], set()
    for key, value in settings:
        if (type(key) is not int or type(value) is not int or
                not 0 <= key < 2**62 or not 0 <= value < 2**62 or key in seen):
            raise ValueError('invalid HTTP3 SETTINGS')
        seen.add(key)
        result.append(['grease'] if key >= 33 and (key - 33) % 31 == 0 else [key, value])
    return sorted(result, key=lambda row: str(row[0]))


@contextmanager
def endpoint(directory):
    # The single per-connection hook below observes decrypted TLS transport
    # parameters before aioquic discards unknown extensions. It is deliberately
    # pinned and exercised by a real local client test; upgrades require review.
    if importlib.metadata.version('aioquic') != DRIVER_VERSION:
        raise RuntimeError('QUIC diagnostic requires aioquic==' + DRIVER_VERSION)
    from aioquic.asyncio import serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.buffer import Buffer
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import HandshakeCompleted, ProtocolNegotiated, ConnectionTerminated
    from aioquic.quic.packet import pull_quic_header, QuicProtocolVersion
    cert, private, spki = certificate(directory)
    records, failures, ready = [], [], queue.Queue(maxsize=1)
    loop = asyncio.new_event_loop()

    class Protocol(QuicConnectionProtocol):
        def __init__(self, quic, *args, **kwargs):
            super().__init__(quic, *args, **kwargs)
            self.http = None
            self.record = {'id': hashlib.sha256(quic.original_destination_connection_id).hexdigest(),
                           'requests': [], 'settings': None, 'long_header_versions': []}
            records.append(self.record)
            original = quic._parse_transport_parameters
            def received(data, from_session_ticket=False):
                original(data, from_session_ticket=from_session_ticket)
                if not from_session_ticket:
                    self.record['transport_parameters'] = parse_transport_parameters(bytes(data))
            quic._parse_transport_parameters = received

        def datagram_received(self, data, addr):
            try:
                header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                if header.version is not None and int(header.version) not in self.record['long_header_versions']:
                    self.record['long_header_versions'].append(int(header.version))
            except ValueError:
                pass  # aioquic decides whether malformed datagrams are fatal.
            super().datagram_received(data, addr)

        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated) and event.alpn_protocol == 'h3':
                self.http = H3Connection(self._quic)
            if isinstance(event, HandshakeCompleted):
                self.record['handshake'] = {'alpn': event.alpn_protocol,
                    'session_resumed': event.session_resumed, 'early_data_accepted': event.early_data_accepted,
                    'version': int(self._quic._version)}
            if isinstance(event, ConnectionTerminated):
                self.record['close_code'] = int(event.error_code)
            if self.http is None:
                return
            for item in self.http.handle_event(event):
                if isinstance(item, HeadersReceived):
                    if len(self.record['requests']) >= 128 or len(item.headers) > 256:
                        failures.append('owned H3 fixture request bound exceeded')
                        self.close()
                        return
                    headers = [[k.decode('ascii'), v.decode('utf-8')] for k, v in item.headers]
                    self.record['requests'].append({'stream': item.stream_id, 'headers': headers,
                        'pseudo_order': [k for k, _ in headers if k.startswith(':')]})
                    target = dict(headers).get(':path', '')
                    if target.split('?', 1)[0] == '/echo':
                        body = json.dumps({'headers': dict(headers), 'connection_id': self.record['id']}).encode()
                        mime = b'application/json'
                    else:
                        body, mime = b'<!doctype html><title>Owned H3 fixture</title>', b'text/html'
                    self.http.send_headers(item.stream_id, [(b':status', b'200'), (b'content-type', mime),
                        (b'content-length', str(len(body)).encode()), (b'accept-ch', HINTS.encode()),
                        (b'cache-control', b'no-store')])
                    self.http.send_data(item.stream_id, body, end_stream=True)
            if self.http.received_settings is not None:
                self.record['settings'] = [[int(k), int(v)] for k, v in self.http.received_settings.items()]
            self.transmit()

    async def owner():
        config = QuicConfiguration(is_client=False, alpn_protocols=['h3'], idle_timeout=10,
                                   supported_versions=[QuicProtocolVersion.VERSION_1])
        config.load_cert_chain(cert, private)
        stop = loop.create_future()
        try:
            server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Protocol)
        except Exception as error:
            ready.put(error)
            return
        port = server._transport.get_extra_info('sockname')[1]
        ready.put((stop, port))
        try:
            await stop
        finally:
            server.close()
            await asyncio.sleep(0)

    def work():
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(lambda _, context: failures.append(str(context.get('exception', context['message']))))
        try:
            loop.run_until_complete(owner())
        finally:
            loop.close()
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    result = ready.get(timeout=15)
    if isinstance(result, Exception):
        worker.join(timeout=5)
        raise result
    stop, port = result
    try:
        yield {'connections': records, 'errors': failures, 'spki': spki}, f'https://127.0.0.1:{port}'
    finally:
        loop.call_soon_threadsafe(stop.set_result, None)
        worker.join(timeout=15)
        if worker.is_alive():
            raise RuntimeError('QUIC endpoint failed to stop')


def assess(report):
    try:
        return _assess(report)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as error:
        return ['malformed QUIC evidence: ' + str(error)]


def _assess(report):
    errors = list(report.get('errors', []))
    if report.get('route') != 'forced-owned-loopback':
        errors.append('missing explicit forced-route qualification')
    runs, connections = report['runs'], report['connections']
    by_id = {c['id']: c for c in connections}
    if len(by_id) != len(connections) or any(not isinstance(i, str) or not re.fullmatch('[0-9a-f]{64}', i) for i in by_id):
        errors.append('duplicate QUIC connection identity')
    if [r['context'] for r in runs] != [0, 1] or any(type(r['context']) is not int for r in runs):
        errors.append('two independent H3 browser contexts were not observed')
    profiles, settings, orders, used = [], [], [], set()
    for run in runs:
        if run.get('navigation_protocol') != 'h3':
            errors.append('navigation did not use H3')
        identity = run['identity']
        wires = [identity['wire'], *run['reuse']]
        ids = {w['connection_id'] for w in wires}
        if len(run['reuse']) != 2 or len(ids) != 1 or not ids <= by_id.keys():
            errors.append('H3 request reuse is missing or unbound')
            continue
        if used & ids:
            errors.append('fresh browser contexts shared a QUIC connection')
        used.update(ids)
        c = by_id[next(iter(ids))]
        handshake = c['handshake']
        if (handshake != {'alpn': 'h3', 'version': 1, 'session_resumed': False, 'early_data_accepted': False} or
                type(handshake['version']) is not int or type(handshake['session_resumed']) is not bool or
                type(handshake['early_data_accepted']) is not bool or
                1 not in c['long_header_versions'] or any(type(v) is not int for v in c['long_header_versions'])):
            errors.append('missing negotiated full QUIC v1/H3 handshake')
        if [wire['headers'].get(':path') for wire in wires] != ['/echo', '/echo?reuse=0', '/echo?reuse=1']:
            errors.append('H3 reuse phases do not match distinct observed requests')
        streams = [r['stream'] for r in c['requests']]
        if any(type(s) is not int or s < 0 or s % 4 != 0 for s in streams) or len(set(streams)) != len(streams):
            errors.append('invalid or reused HTTP3 request stream')
        profiles.append(canonical_parameters(c['transport_parameters']))
        settings.append(canonical_settings(c['settings']))
        for wire in wires:
            requests = [r for r in c['requests'] if dict(r['headers']) == wire['headers']]
            if len(requests) != 1:
                errors.append('H3 response is not bound to a server-observed request')
                continue
            request = requests[0]
            order = [k for k, _ in request['headers'] if k.startswith(':')]
            if (request.get('pseudo_order') != order or len(order) != 4 or
                    set(order) != {':method', ':authority', ':scheme', ':path'} or
                    [k for k, _ in request['headers'][:4]] != order):
                errors.append('invalid HTTP3 pseudo-header order evidence')
            orders.append(order)
        scope = {'identity': {'value': {'ua': identity['userAgent'], 'languages': identity['languages'],
                    'uaData': identity['userAgentData']}}, 'http': {'status': 'observed', 'value': identity['wire']}}
        errors.extend(header_errors(scope, require_hints=True))
    for values, label in ((profiles, 'QUIC transport parameters'), (settings, 'H3 SETTINGS'), (orders, 'H3 pseudo-header order')):
        if not values or any(value != values[0] for value in values[1:]):
            errors.append(label + ' changed across contexts or were not observed')
    return sorted(set(errors))


def run(browser, headed=False):
    report = {'schema_version': 1, 'browser_sha256': launch.pool.file_hash(browser), 'errors': [],
              'collected_at': datetime.now(timezone.utc).isoformat(), 'runs': [], 'connections': [],
              'route': 'forced-owned-loopback', 'driver': {'aioquic': DRIVER_VERSION},
              'qualification': {'proxy': 'not_tested', 'dns': 'not_tested', 'physical_network': 'not_attested',
                  'alt_svc_discovery': 'not_tested', 'migration': 'not_tested', 'zero_rtt': 'not_tested',
                  'unknown_parameters': 'length and payload hash only', 'ticket_contents': 'not_recorded'}}
    try:
        from playwright.sync_api import sync_playwright
        with tempfile.TemporaryDirectory(prefix='chromix-quic-') as directory:
            with endpoint(Path(directory)) as (server, origin), sync_playwright() as pw:
                args = [*launch.NATIVE_ARGS, '--enable-quic', '--origin-to-force-quic-on=' + origin.split('://')[1],
                        '--ignore-certificate-errors-spki-list=' + server['spki']]
                report['launch_args'] = args
                instance = pw.chromium.launch(executable_path=str(browser.resolve()), headless=not headed,
                    chromium_sandbox=True, args=args)
                try:
                    report['browser_version'] = instance.version
                    for i in range(2):
                        context = instance.new_context(no_viewport=True)
                        try:
                            page = context.new_page()
                            page.goto(origin, wait_until='load', timeout=30000)
                            identity = page.evaluate(launch.bounded(IDENTITY), None)
                            reuse = page.evaluate(launch.bounded('''async () => {
                              const out=[]; for (let i=0;i<2;i++)
                                out.push(await (await fetch('/echo?reuse='+i,{cache:'no-store'})).json());
                              return out;
                            }'''), None)
                            report['runs'].append({'context': i, 'identity': identity, 'reuse': reuse,
                                'navigation_protocol': page.evaluate("performance.getEntriesByType('navigation')[0].nextHopProtocol")})
                        finally:
                            context.close()
                finally:
                    instance.close()
            report['connections'] = copy.deepcopy(server['connections'])
            report['errors'].extend(server['errors'])
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    if launch.pool.file_hash(browser) != report['browser_sha256']:
        report['errors'].append('browser executable changed')
    report['errors'] = assess(report)
    report['status'] = 'failed' if report['errors'] else 'passed'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--headed', action='store_true')
    args = parser.parse_args(argv)
    if not args.browser.is_file() or args.output.exists():
        parser.error('use an existing executable and a new report path')
    report = run(args.browser, args.headed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': report['status'], 'errors': report['errors']}))
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())

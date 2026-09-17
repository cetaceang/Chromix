"""P0 probes are evidence checks, not claims of physical-device equivalence."""
from copy import deepcopy
from http.client import HTTPConnection
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_p0_audit as audit
import device_wire_evidence as wire
from chromix._device_headers import header_errors, parse_hint
from chromix import _device_launch as launch
from test_device_pool import observation


def http_sample():
    data = {'brands':[{'brand':'Fixture', 'version':'152'}], 'mobile':False,
            'platform':'Windows', 'architecture':'x86', 'bitness':'64',
            'platformVersion':'19.0.0', 'fullVersionList':[{'brand':'Fixture', 'version':'152.0.1.2'}],
            'model':'', 'wow64':False}
    headers = {'user-agent':'fixture', 'accept-language':'zh-CN,zh;q=0.9',
               'sec-ch-ua':'"Fixture";v="152"', 'sec-ch-ua-mobile':'?0',
               'sec-ch-ua-platform':'"Windows"', 'sec-ch-ua-arch':'"x86"',
               'sec-ch-ua-bitness':'"64"', 'sec-ch-ua-platform-version':'"19.0.0"',
               'sec-ch-ua-full-version-list':'"Fixture";v="152.0.1.2"',
               'sec-ch-ua-model':'""', 'sec-ch-ua-wow64':'?0'}
    return {'identity':{'value':{'ua':'fixture', 'languages':['zh-CN'], 'uaData':data}},
            'http':{'status':'observed', 'value':{'headers':headers}}}


def test_http_js_identity_matches():
    assert header_errors(http_sample()) == []


@pytest.mark.parametrize('field,value', [('user-agent','other'), ('accept-language','en-US'),
    ('sec-ch-ua-arch','"arm"'), ('sec-ch-ua-bitness','64'), ('sec-ch-ua-mobile','false'),
    ('sec-ch-ua','"Fixture";v="152",bad')])
def test_http_mismatches_fail(field, value):
    sample = http_sample()
    sample['http']['value']['headers'][field] = value
    assert header_errors(sample)


def test_worker_missing_hints_are_not_invented():
    sample = http_sample()
    headers = sample['http']['value']['headers']
    sample['http']['value']['headers'] = {k:v for k,v in headers.items() if not k.startswith('sec-ch-ua')}
    assert header_errors(sample)
    assert header_errors(sample, require_hints=False) == []
    sample['http']['value']['headers']['sec-ch-ua-bitness'] = '"32"'
    assert header_errors(sample, require_hints=False)


def test_brand_order_and_escaped_names():
    assert parse_hint('"B";v="2", "A";v="1"', 'brands') == [('A','1'), ('B','2')]
    assert parse_hint('"A\\"B";v="1"', 'brands') == [('A"B','1')]


def test_runtime_execution_failure_is_rejected():
    sample = observation()
    for value in sample.values():
        value['probeVersion'] = 2
        value['execution']['runtime'] = {'status':'error', 'reason':'fixture'}
    assert any('execution self-test' in e for e in launch.pool.observation_errors(sample))


def test_isolation_is_context_specific():
    sample = observation()
    for scope in ('window','iframe','worker'):
        sample[scope]['execution'].update(isolated=True, sab=True)
    assert not launch.pool.observation_errors(sample)
    sample['shared_worker']['execution'].update(isolated=False, sab=True)
    assert any('SAB exposed' in e for e in launch.pool.observation_errors(sample))


def test_http_not_part_of_stable_device_snapshot():
    sample = observation()
    sample['window']['http'] = http_sample()['http']
    assert 'http' not in launch.pool.stable_observation(sample)['window']


def test_audit_requires_v2_and_isolated_execution():
    errors = audit.evaluate(observation(), True)
    assert any('requires probe v2' in e for e in errors)
    assert any('isolation/SAB' in e for e in errors)


def v2_observation():
    sample = observation()
    for value in sample.values():
        value.update(deepcopy(http_sample()))
        value['identity']['status'] = 'observed'
        value['probeVersion'] = 2
        value['execution']['runtime'] = {'status':'observed', 'value':{
            'scalar':42, 'simd':7, 'memoryGrowth':True, 'maximumEnforced':True, 'atomics':None}}
        value['webgl']['value']['backend'] = {
            'shader':True, 'textureRGBA':[0,255,0,255], 'requestExtensions':True}
    return sample


@pytest.mark.parametrize('fault', ['scalar', 'simd', 'memoryGrowth', 'maximumEnforced', 'atomics'])
def test_success_label_does_not_hide_bad_execution(fault):
    sample = v2_observation()
    assert not launch.pool.observation_errors(sample)
    sample['worker']['execution']['runtime']['value'][fault] = 'incorrect'
    assert any('execution self-test' in e for e in launch.pool.observation_errors(sample))


def test_success_label_does_not_hide_bad_gpu_or_fonts():
    sample = v2_observation()
    sample['window']['webgl']['value']['backend']['textureRGBA'] = [0,0,0,0]
    sample['window']['fonts'] = {'status':'observed', 'value':{'samples':[]}}
    errors = launch.pool.observation_errors(sample)
    assert any('backend self-test' in e for e in errors)
    assert any('incomplete sample matrix' in e for e in errors)


def test_sab_requires_actual_shared_wasm_memory():
    value = v2_observation()['window']
    value['execution'].update(sab=True, isolated=True)
    value['execution']['runtime']['value']['atomics'] = True
    assert 'shared Wasm memory self-test failed or missing' in launch.pool.capability_errors(value)
    value['execution']['sharedMemory'] = {'status':'observed', 'value':True}
    assert not launch.pool.capability_errors(value)


@pytest.mark.parametrize('isolated', [False, True])
def test_probe_server_echo_and_isolation(isolated):
    with launch.probe_server(isolated=isolated) as origin:
        connection = HTTPConnection(origin.removeprefix('http://'))
        try:
            connection.request('GET', '/headers', headers={'User-Agent':'fixture', 'Sec-CH-UA-Arch':'"x86"'})
            response = connection.getresponse()
            assert response.status == 200
            assert response.getheader('Cross-Origin-Opener-Policy') == ('same-origin' if isolated else None)
            assert response.getheader('Cross-Origin-Embedder-Policy') == ('require-corp' if isolated else None)
            assert "'wasm-unsafe-eval'" in response.getheader('Content-Security-Policy')
            assert 'Sec-CH-UA-Arch' in response.getheader('Accept-CH')
            headers = json.loads(response.read())['headers']
            assert headers['user-agent'] == 'fixture' and headers['sec-ch-ua-arch'] == '"x86"'
            connection.request('GET', '/headers', headers={'Host':'unexpected.example'})
            response = connection.getresponse()
            assert response.status == 403
            response.read()
        finally:
            connection.close()


def test_v2_record_rejects_http_mismatch(tmp_path):
    from test_device_pool import bundle, seal
    record = bundle(tmp_path)
    path = tmp_path / 'browser.json'
    browser = launch.pool.load_json(path)
    browser['observations'] = [v2_observation() for _ in range(3)]
    record['device']['surfaces'] = launch.pool.stable_observation(browser['observations'][0])
    def save():
        path.write_text(json.dumps(browser), encoding='utf-8')
        record['evidence']['browser']['sha256'] = launch.pool.file_hash(path)
        seal(record)
    save()
    launch.pool.validate_record(record, tmp_path)
    browser['observations'][1]['worker']['http']['value']['headers']['user-agent'] = 'different'
    save()
    with pytest.raises(ValueError, match='User-Agent'):
        launch.pool.validate_record(record, tmp_path)


def test_captured_egress_checks_are_not_route_attestation():
    packets = [{'_source':{'layers':{'frame':{'frame.number':'1'},
        'ip':{'ip.src':'192.0.2.2', 'ip.dst':'192.0.2.3'},
        'tcp':{'tcp.dstport':'8080'}}}}]
    policy = {'client_ips':['192.0.2.2'], 'allowed_egress':[{'protocol':'tcp','ip':'192.0.2.3','port':8080}]}
    result = wire.route_check(packets, policy)
    assert result['status'] == 'observed_match' and not result['route_verified']
    changed = deepcopy(policy)
    changed['allowed_egress'] = []
    assert wire.route_check(packets, changed)['status'] == 'mismatch'
    assert wire.route_check([], policy)['status'] == 'inconclusive'
    packets[0]['_source']['layers']['ip']['ip.src'] = ['192.0.2.2','192.0.2.4']
    assert wire.route_check(packets, policy)['status'] == 'inconclusive'


@pytest.mark.parametrize('policy', [{}, {'client_ips':[], 'allowed_egress':[]},
    {'client_ips':['192.0.2.2'], 'allowed_egress':[{'protocol':'udp','ip':'192.0.2.3','port':True}]}])
def test_route_policy_rejects_malformed_input(policy):
    with pytest.raises(ValueError):
        wire.route_check([], policy)


@pytest.mark.parametrize('limit,allowed,status,exit_code', [
    (10, True, 'observed_match', 0), (1, True, 'inconclusive', 1),
    (10, False, 'mismatch', 1)])
def test_wire_cli_reports_route_result(tmp_path, monkeypatch, capsys, limit, allowed, status, exit_code):
    from types import SimpleNamespace
    capture, policy, output = (tmp_path / name for name in ('capture.pcap', 'policy.json', 'output.json'))
    capture.write_bytes(b'synthetic fixture, not a packet capture')
    policy.write_text(json.dumps({'client_ips':['192.0.2.2'], 'allowed_egress':[
        {'protocol':'tcp','ip':'192.0.2.3','port':8080}] if allowed else []}), encoding='utf-8')
    packets = [{'_source':{'layers':{'frame':{'frame.number':'1'},
        'ip':{'ip.src':'192.0.2.2','ip.dst':'192.0.2.3'}, 'tcp':{'tcp.dstport':'8080'}}}}]
    monkeypatch.setattr(wire.subprocess, 'run', lambda *a, **k: SimpleNamespace(stdout=json.dumps(packets), stderr=''))
    assert wire.main(['--pcap',str(capture),'--route-policy',str(policy),
                      '--output',str(output),'--max-packets',str(limit)]) == exit_code
    report = json.loads(output.read_text())
    assert report['route_check']['status'] == status
    assert report['route_check']['route_verified'] is False
    assert report['packet_details'][0]['fields']['tcp.dstport'] == ['8080']
    assert json.loads(capsys.readouterr().out)['status'] == status


@pytest.mark.parametrize('failure_scope', [None, 'iframe', 'worker'])
def test_canvas_collector_keeps_all_scopes_without_device_backends(monkeypatch, failure_scope):
    import canvas_chain_audit as canvas

    calls = []
    class Page:
        def goto(self, origin, **kwargs):
            calls.append(('goto', origin, kwargs))
        def frame(self, *, url):
            assert url == 'http://127.0.0.1:8123/frame'
            return Frame()
        def evaluate(self, script, argument=None):
            scope = argument or 'window'
            calls.append(scope)
            assert script == (launch.WORKER_EVAL if argument else launch.PROBE_EVAL)
            if scope == failure_scope:
                raise RuntimeError(scope + ' failed')
            return {'scope':scope}
        def close(self):
            calls.append('close')
    class Frame:
        def evaluate(self, script):
            assert script == launch.PROBE_EVAL
            calls.append('iframe')
            if failure_scope == 'iframe':
                raise RuntimeError('iframe failed')
            return {'scope':'iframe'}
    class Context:
        def new_page(self):
            return Page()
    def unexpected(*args):
        raise AssertionError('Canvas-only page must not request font/GPU evidence')
    monkeypatch.setattr(launch.fonts, 'collect', unexpected)
    monkeypatch.setattr(launch.gpu_backend, 'collect_system', unexpected)
    if failure_scope:
        with pytest.raises(RuntimeError, match=failure_scope + ' failed'):
            canvas.collect_live(Context(), 'http://127.0.0.1:8123')
    else:
        observed = canvas.collect_live(Context(), 'http://127.0.0.1:8123')
        assert observed == {scope:{'scope':scope} for scope in launch.pool.SCOPES}
        assert calls[1:-1] == list(launch.pool.SCOPES)
    assert calls[-1] == 'close'
    assert calls[0][2] == {'wait_until':'load', 'timeout':launch.DEFAULT_TIMEOUT}

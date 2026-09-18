"""Invented observations test admission; they are not native-browser results."""
import base64
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fingerprint_backend_audit as backend
import fingerprint_media_policy_audit as media
import fingerprint_acceptance as acceptance


def clock_observation(quantum, start=0):
    step = quantum or 10
    origin = 1789390000000 // step * step
    samples = [{'now': start // step * step + i * step, 'origin': origin} for i in range(1, 7)]
    for sample in samples:
        sample.update(wall=origin + sample['now'], event=sample['now'],
                      temporal=str((origin + sample['now']) * 1000000))
    return {'samples': samples, 'timezone': 'America/New_York', 'dst': ['01:59', '03:00', '01:59', '01:00'],
        'offsets': [300, 240, 240, 300], 'locale': {'hourCycle': 'h23', 'numberingSystem': 'latn'},
        'callbacks': {'raf': {'timestamp': samples[-1]['now'], 'now': samples[-1]['now']},
                      'idle': {'remaining': step, 'now': samples[-1]['now'], 'timedOut': False}}}


def float32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def samples_hash(samples):
    return hashlib.sha256(struct.pack('<4096f', *samples)).hexdigest()


def audio_observation(name):
    source = [float32(math.sin(i / 37) * 0.47) for i in range(4096)]
    # Two invented rounding thresholds exercise the evidence validator, not
    # the C++ policy (which has separate compiled-method tests).
    threshold = 0.3 if name in ('isolated', 'restart') else 0.7
    samples = source if name == 'native' else [
        math.copysign(math.floor(abs(v) * 2**20 + threshold) / 2**20, v) for v in source]
    digest = samples_hash(samples)
    return {'samples': samples, 'hash': digest, 'copyHash': digest, 'workletHash': digest,
        'sourceHash': samples_hash(source), 'sampleRate': 44100, 'channels': 1, 'frames': 4096,
        'mutable': True, 'analyserMatches': True,
        'playback': {'inputHash': digest, 'sameSamples': True, 'state': 'running', 'frames': 4096,
                     'sampleRate': 44100, 'baseLatency': 0.01, 'outputLatency': None}}


def backend_report():
    result = {'schema_version': 1, 'status': 'passed', 'errors': [], 'runs': [],
        'browser_sha256': 'a' * 64, 'browser_version': '152.0.7977.82',
        'probe_sha256': backend.launch.pool.file_hash(backend.PROBE),
        'font_asset_sha256': backend.launch.pool.file_hash(backend.AUTHOR_FONT), 'restricted_family': 'Fixture Family'}
    caps = {'uvpaa': {'status': 'observed', 'value': False}, 'keyboard': {'status': 'observed', 'entries': [['KeyA', 'a']]},
            'speech': [{'name': 'Fixture voice', 'lang': 'en-US', 'local': True, 'default': True}],
            'pdf': True, 'plugins': [{'name': 'Fixture PDF viewer', 'filename': 'internal-pdf-viewer',
                                     'types': ['application/pdf']}]}
    for name in backend.CASES:
        mixed = name in ('isolated', 'restart')
        quantum = 0 if name == 'native' else 7 if mixed else 11
        queries = dict.fromkeys(backend.QUERY_KEYS, mixed)
        queries.update(coarse=False, none=not mixed)
        preferences = {'queries': queries, 'styles': deepcopy(queries), 'maxTouchPoints': 5 if mixed else 0,
            'touchEvent': mixed, 'author': {'background': 'rgb(0, 0, 0)' if mixed else 'rgb(3, 7, 11)',
                                          'color': 'rgb(241, 239, 233)'}}
        run = {'name': name, 'launch_args': backend.case_args(name, result['restricted_family'], caps),
            'preferences': preferences, 'preferences_reloaded': deepcopy(preferences),
            'capabilities': deepcopy(caps), 'audio': audio_observation(name),
            'clocks': {key: clock_observation(quantum, {'after_freeze': 200, 'history': 400}.get(key, 0))
                for key in ('window', 'after_freeze', 'history', 'reloaded', 'iframe', 'oopif', 'dedicated', 'shared', 'service')},
            'oopif_observed': True,
            'lifecycle_events': [{'name': event, 'trusted': True, 'timestamp': (quantum or 10) * (10 + 2 * i),
                                 'now': (quantum or 10) * (10 + 2 * i)} for i, event in enumerate(('freeze', 'resume'))],
            'history_events': [{'name': 'pageshow', 'persisted': True}],
            'input_events': [{'name': 'keydown', 'key': 'a', 'trusted': True, 'timestamp': quantum * 3}],
            'fonts': [{'family': family, 'text': text, 'platformFonts': [{'familyName': result['restricted_family'], 'glyphCount': 4}]}
                for family in ('serif', 'sans-serif', 'monospace', 'system-ui') for text in ('Aa09', '中文', '😀', '∑', '\u0378')],
            'local_fonts': {'status': 'observed', 'families': [result['restricted_family']]},
            'author_font': {'status': 'loaded', 'width': 42, 'platformFonts': [{'isCustomFont': True, 'glyphCount': 4}]}}
        if mixed:
            run['input_events'].append({'name': 'pointerdown', 'pointerType': 'touch', 'trusted': True, 'timestamp': 21})
        result['runs'].append(run)
    return result


def test_backend_recomputes_queries_clock_grids_samples_and_restarts():
    assert backend.assess(backend_report()) == ([], [])


@pytest.mark.parametrize('mutate', [
    lambda r: r['runs'].pop(),
    lambda r: r.update(probe_sha256='0' * 64),
    lambda r: r.update(font_asset_sha256='0' * 64),
    lambda r: r.update(restricted_family='Unobserved Font'),
    lambda r: r['runs'][1]['launch_args'].append('--uxr-timer-resolution=0'),
    lambda r: r['runs'][1]['preferences']['styles'].update(dark=False),
    lambda r: r['runs'][1]['preferences'].update(maxTouchPoints=0),
    lambda r: r['runs'][1]['preferences'].update(touchEvent=False),
    lambda r: r['runs'][1]['preferences']['author'].update(background='rgb(3, 7, 11)'),
    lambda r: r['runs'][3]['preferences']['author'].update(color='rgb(0, 0, 0)'),
    lambda r: r['runs'][1]['clocks'].pop('service'),
    lambda r: r['runs'][1].update(oopif_observed=False),
    lambda r: r['runs'][1]['clocks']['oopif']['samples'][0].update(now=0.125),
    lambda r: r['runs'][1]['lifecycle_events'].pop(),
    lambda r: r['runs'][1]['clocks']['history']['samples'][0].update(now=7),
    lambda r: r['runs'][1]['clocks']['shared']['samples'][0].update(now=0.125),
    lambda r: r['runs'][1]['clocks']['dedicated']['samples'][0].update(wall=0),
    lambda r: r['runs'][1]['clocks']['service']['samples'][0].update(temporal='123'),
    lambda r: r['runs'][1]['clocks']['window']['samples'][0].update(temporal=123),
    lambda r: r['runs'][1]['clocks']['iframe'].update(offsets=[300] * 4),
    lambda r: r['runs'][1]['clocks']['window'].update(timezone='UTC'),
    lambda r: r['runs'][1]['clocks']['window']['locale'].update(hourCycle='h12'),
    lambda r: r['runs'][1]['clocks']['window']['callbacks']['raf'].update(timestamp=1.5),
    lambda r: r['runs'][1]['clocks']['window']['callbacks']['idle'].update(remaining=0.123),
    lambda r: r['runs'][1]['clocks']['after_freeze']['samples'][0].update(origin=0),
    lambda r: r['runs'][1]['input_events'].pop(),
    lambda r: r['runs'][1]['input_events'][0].update(trusted=False),
    lambda r: r['runs'][1]['input_events'][0].update(timestamp=1),
    lambda r: r['runs'][1]['audio']['samples'].__setitem__(1, 0.1),
    lambda r: r['runs'][1]['audio'].update(copyHash='0' * 64),
    lambda r: r['runs'][1]['audio'].update(workletHash='0' * 64),
    lambda r: r['runs'][1]['audio'].update(analyserMatches=False),
    lambda r: r['runs'][1]['audio'].update(sourceHash='0' * 64),
    lambda r: r['runs'][1]['audio'].update(mutable=False),
    lambda r: r['runs'][1]['audio']['playback'].update(sameSamples=False),
    lambda r: r['runs'][1]['audio']['playback'].update(baseLatency=-1),
    lambda r: r['runs'][2].update(audio=deepcopy(r['runs'][3]['audio'])),
    lambda r: r['runs'][3].update(audio=deepcopy(r['runs'][1]['audio'])),
    lambda r: r['runs'][1]['fonts'][0]['platformFonts'][0].update(familyName='Host Font'),
    lambda r: r['runs'][1]['fonts'][0]['platformFonts'].clear(),
    lambda r: r['runs'][1]['local_fonts']['families'].append('Host Font'),
    lambda r: r['runs'][1]['author_font']['platformFonts'][0].update(isCustomFont=False),
    lambda r: r['runs'][1]['capabilities']['uvpaa'].update(value=True),
    lambda r: r['runs'][1]['capabilities'].update(speech=[{'name': 'Invented voice'}]),
    lambda r: r['runs'][1]['capabilities'].update(pdf=False),
])
def test_backend_saved_pass_cannot_override_broken_observations(mutate):
    report = backend_report()
    mutate(report)
    assert backend.assess(report)[0]
    assert acceptance.assess_suite('backend_policy', report, 'a' * 64, '152.0.7977.82')[0]


def test_backend_unavailable_optional_features_are_recomputed_gaps():
    report = backend_report()
    for run in report['runs']:
        run['history_events'] = [{'name': 'pageshow', 'persisted': False}]
        run['local_fonts'] = {'status': 'unavailable', 'error': 'NotAllowedError'}
        for clock in run['clocks'].values():
            for sample in clock['samples']:
                sample['temporal'] = None
    errors, gaps = backend.assess(report)
    assert not errors
    assert 'native.bfcache' in gaps and 'isolated.service.Temporal' in gaps
    assert 'other_seed.local_fonts' in gaps


def test_empty_asynchronous_speech_inventory_does_not_attest_backend_absence():
    report = backend_report()
    for run in report['runs']:
        run['capabilities']['speech'] = []
    errors, gaps = backend.assess(report)
    assert not errors
    assert gaps == sorted(name + '.speech_inventory' for name in backend.CASES)


@pytest.mark.parametrize(('feature', 'value'), [
    ('uvpaa', {'status': 'observed', 'value': 'false'}),
    ('uvpaa', {'status': 'unavailable'}),
    ('keyboard', {'status': 'ignored'}),
    ('keyboard', {'status': 'observed', 'entries': 'KeyA=a'}),
    ('keyboard', {'status': 'observed', 'entries': [['KeyA', 'a'], ['KeyA', 'b']]}),
    ('plugins', [{'name': 'PDF', 'filename': 'internal-pdf-viewer', 'types': 'application/pdf'}]),
])
def test_matching_malformed_capability_inventories_do_not_pass(feature, value):
    report = backend_report()
    for run in report['runs']:
        run['capabilities'][feature] = deepcopy(value)
    # Recompute the intentional negative hint so a launch-argument mismatch
    # cannot be the reason this malformed but identical inventory is rejected.
    for run in report['runs']:
        run['launch_args'] = backend.case_args(run['name'], report['restricted_family'], report['runs'][0]['capabilities'])
    assert backend.assess(report)[0]
    assert acceptance.assess_suite('backend_policy', report, 'a' * 64, '152.0.7977.82')[0]


def test_empty_keyboard_inventory_remains_an_observation_gap():
    report = backend_report()
    for run in report['runs']:
        run['capabilities']['keyboard']['entries'] = []
    errors, gaps = backend.assess(report)
    assert not errors
    assert gaps == sorted(name + '.keyboard_inventory' for name in backend.CASES)


def recorded(family='vp8'):
    data = b'owned invented codec fixture'
    return {'status': 'recorded', 'data': base64.b64encode(data).decode(), 'bytes': len(data),
            'mime': 'video/webm;codecs=' + family}


def decoded(frames=False):
    return {'status': 'decoded', **({'frames': [{'width': 64, 'height': 64}]} if frames else {'width': 64, 'height': 64})}


def rejection():
    return {'status': 'rejected', 'error': 'NotSupportedError'}


def media_report():
    report = {'schema_version': 1, 'status': 'passed', 'errors': [], 'runs': [],
        'browser_sha256': 'a' * 64, 'browser_version': '152.0.7977.82',
        'probe_sha256': media.launch.pool.file_hash(media.PROBE)}
    for name, disabled in media.CASES.items():
        observation = {'families': {}, 'apis': dict.fromkeys(('encoder', 'decoder', 'recorder', 'mse'), True),
                       'audio': {'status': 'recorded', 'bytes': 123, 'mime': 'audio/webm;codecs=opus'}}
        for family in media.FAMILIES:
            allowed = family not in disabled
            observation['families'][family] = {**dict.fromkeys(media.API_KEYS, allowed),
                'rtcSend': int(allowed), 'rtcReceive': int(allowed), 'canPlay': 'probably' if allowed else '',
                'encoding': dict.fromkeys(('supported', 'smooth', 'powerEfficient'), allowed),
                'decoding': dict.fromkeys(('supported', 'smooth', 'powerEfficient'), allowed),
                'encoded': {'status': 'encoded', 'config': {'codec': family},
                    'chunks': [{'data': 'eHg=', 'type': 'key', 'timestamp': 0}]} if allowed else rejection(),
                'recorded': recorded(family) if allowed else rejection(),
                'decoded': decoded(True) if allowed else rejection(),
                'playback': decoded() if allowed else rejection(), 'mse': decoded() if allowed else rejection()}
        observation['defaultRecorder'] = rejection() if name == 'disabled' else {**recorded(), 'playback': decoded()}
        observation['rtc'] = rejection() if name == 'disabled' else {
            'status': 'decoded', 'frames': 3, 'bytes': 456, 'codec': 'video/VP8', 'errors': [],
            'formats': [f for f in media.FAMILIES if f not in disabled]}
        report['runs'].append({'name': name, 'launch_args': media.case_args(name), 'observation': observation})
    return report


def test_media_revalidates_native_fixtures_and_actual_codec_rejection():
    assert media.assess(media_report()) == ([], [])


@pytest.mark.parametrize('mutate', [
    lambda r: r['runs'].pop(),
    lambda r: r.update(probe_sha256='0' * 64),
    lambda r: r['runs'][1]['launch_args'].clear(),
    lambda r: r['runs'][0]['observation']['apis'].update(encoder=False),
    lambda r: r['runs'][0]['observation']['families']['vp8']['encoded'].update(chunks=[]),
    lambda r: r['runs'][0]['observation']['families']['vp8']['recorded'].update(data='!'),
    lambda r: r['runs'][0]['observation']['families']['vp8']['recorded'].update(bytes=0),
    lambda r: r['runs'][0]['observation']['families']['vp8']['decoded'].update(frames=[]),
    lambda r: r['runs'][0]['observation']['families']['vp8']['mse'].update(width=32),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(encoderSupported=True),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(canPlay='maybe'),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(rtcReceive=1),
    lambda r: r['runs'][1]['observation']['families']['vp8']['encoding'].update(supported=True),
    lambda r: r['runs'][1]['observation']['families']['vp8']['decoding'].update(smooth=True),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(encoded={'status': 'encoded', 'chunks': []}),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(recorded=recorded()),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(decoded=decoded(True)),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(playback=decoded()),
    lambda r: r['runs'][1]['observation']['families']['vp8'].update(mse=decoded()),
    lambda r: r['runs'][1]['observation']['families']['vp8']['recorded'].update(error='Error:backend probe timed out'),
    lambda r: r['runs'][1]['observation'].update(defaultRecorder=recorded()),
    lambda r: r['runs'][1]['observation'].update(rtc={'status': 'offered', 'formats': ['vp8']}),
    lambda r: r['runs'][1]['observation']['rtc'].update(error='ReferenceError'),
    lambda r: r['runs'][1]['observation']['audio'].update(bytes=0),
    lambda r: r['runs'][2]['observation']['defaultRecorder'].update(mime='video/webm;codecs=vp9'),
    lambda r: r['runs'][2]['observation']['rtc'].update(codec='video/H264'),
    lambda r: r['runs'][2]['observation']['rtc'].update(frames=0),
    lambda r: r['runs'][2]['observation']['families']['vp8'].update(recorderSupported=False),
])
def test_media_saved_pass_cannot_hide_operation_failures(mutate):
    report = media_report()
    mutate(report)
    assert media.assess(report)[0]
    assert acceptance.assess_suite('media_policy', report, 'a' * 64, '152.0.7977.82')[0]


@pytest.mark.parametrize('key', ('encoding', 'decoding'))
def test_missing_media_capabilities_result_is_explicit_and_does_not_abort_other_checks(key):
    report = media_report()
    for run in report['runs']:
        run['observation']['families']['h264'][key] = None
    errors, gaps = media.assess(report)
    assert any('h264: missing MediaCapabilities result: ' + key in error for error in errors)
    assert not any("NoneType" in error for error in errors)
    assert gaps == []


def test_missing_media_capabilities_retains_disabled_operation_failures_and_gaps():
    report = media_report()
    report['runs'][1]['observation']['families']['h264']['encoding'] = None
    report['runs'][1]['observation']['families']['h264']['encoded'] = {'status': 'encoded', 'config': {'codec': 'h264'},
        'chunks': [{'data': 'eHg=', 'type': 'key', 'timestamp': 0}]}
    errors, gaps = media.assess(report)
    assert any('disabled codec still advertised' in error for error in errors) is False
    assert any('disabled encoded operation was not rejected' in error for error in errors)
    assert any('missing MediaCapabilities result: encoding' in error for error in errors)


def test_missing_media_capabilities_does_not_hide_native_fixture_gaps():
    report = media_report()
    for run in report['runs']:
        row = run['observation']['families']['hevc']
        row['encoding'] = None
        if run['name'] == 'native':
            row.update(**dict.fromkeys(media.API_KEYS, False), canPlay='', rtcSend=0, rtcReceive=0,
                       encoded={'status': 'unavailable'}, recorded={'status': 'unavailable'})
        row.update(decoded={'status': 'unavailable'}, playback={'status': 'unavailable'}, mse={'status': 'unavailable'})
    errors, gaps = media.assess(report)
    assert any('missing MediaCapabilities result: encoding' in error for error in errors)
    assert 'native.hevc.native_encoder' in gaps
    assert 'disabled.hevc.decoded.no_native_fixture' in gaps


def test_missing_hardware_codec_is_a_gap_not_fabricated_operation_coverage():
    report = media_report()
    for run in report['runs']:
        row = run['observation']['families']['hevc']
        if run['name'] == 'native':
            row.update(**dict.fromkeys(media.API_KEYS, False), canPlay='', rtcSend=0, rtcReceive=0,
                       encoded={'status': 'unavailable'}, recorded={'status': 'unavailable'})
        row.update(decoded={'status': 'unavailable'}, playback={'status': 'unavailable'}, mse={'status': 'unavailable'})
    errors, gaps = media.assess(report)
    assert not errors
    assert 'disabled.hevc.decoded.no_native_fixture' in gaps
    assert 'native.hevc.native_encoder' in gaps


def test_native_encode_without_a_native_decode_control_retains_rejection_gap():
    report = media_report()
    native = report['runs'][0]['observation']['families']['hevc']
    native.update(decoderSupported=False, canPlay='', mseSupported=False,
                  decoded=rejection(), playback=rejection(), mse={'status': 'unavailable'})
    errors, gaps = media.assess(report)
    assert not errors
    assert 'disabled.hevc.decoded.no_native_decode_control' in gaps
    assert 'vp8_only.hevc.playback.no_native_decode_control' in gaps


@pytest.mark.parametrize('report', [None, [], {}, {'runs': []}, {'runs': [None]}])
def test_malformed_reports_fail_closed(report):
    assert backend.assess(report)[0]
    assert media.assess(report)[0]


def test_valid_reports_are_rechecked_by_release_gate():
    for name, report in (('backend_policy', backend_report()), ('media_policy', media_report())):
        assert acceptance.assess_suite(name, report, 'a' * 64, '152.0.7977.82') == ([], [])


def test_owned_assets_workers_and_font_responses():
    with backend.server() as origin:
        for path, content in [('/probe.js', backend.PROBE.read_bytes()), ('/author.ttf', backend.AUTHOR_FONT.read_bytes()),
                              ('/audio-worklet.js', backend.WORKLET.encode())]:
            with urllib.request.urlopen(origin + path, timeout=5) as response:
                assert response.read() == content
        for path in backend.WORKERS:
            with urllib.request.urlopen(origin + path, timeout=5) as response:
                assert response.read().startswith(b"importScripts('/probe.js');")
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(origin, headers={'Host': 'external.invalid'}), timeout=5)
        assert error.value.code == 403


def test_worklet_tap_crops_exact_frames_without_changing_graph_output(tmp_path):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required to execute the fixture worklet')
    script = tmp_path / 'worklet.cjs'
    script.write_text("""const vm=require('node:vm'), assert=require('node:assert/strict');
const messages=[]; let Processor;
const context={currentFrame:0,Float32Array,AudioWorkletProcessor:class {constructor(){this.port={postMessage:m=>messages.push(m)};}},
  registerProcessor:(name,ctor)=>{assert.equal(name,'backend-tap');Processor=ctor;}};
vm.createContext(context);
""" + 'vm.runInContext(' + json.dumps(backend.WORKLET) + ',context);\n' + """
const p=new Processor({processorOptions:{start:64,frames:301}});
for(let block=0;block<4;block++) {
  context.currentFrame=block*128;
  const input=Float32Array.from({length:128},(_,i)=>block*128+i+1), output=new Float32Array(128);
  const alive=p.process([[input]],[[output]]);assert.deepEqual(input,output);
  assert.equal(alive,block<2);
}
const result=new Float32Array(301);
for(const message of messages)result.set(message.samples,message.offset);
assert.equal(messages.reduce((n,m)=>n+m.samples.length,0),301);
assert.deepEqual(result,Float32Array.from({length:301},(_,i)=>i+65));
""", encoding='utf-8')
    subprocess.run([node, str(script)], check=True, timeout=15, capture_output=True, text=True)

"""Invented fixtures exercise admission branches; none are physical pool samples."""
import base64
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'sdk/python'))
from chromix import _device_render as render, device_pool as pool
from chromix._device_probe import PROBE_VERSION, probe_hash, probe_source, ASSETS
from chromix import _device_fonts as fonts
from test_device_pool import bundle as legacy_bundle, seal
from test_device_p0 import v2_observation
from test_canvas_chain_audit import template as chain_template, codec_v2_template, codec_export
from test_fingerprint_runtime_audits import render_report
from gpu_backend_fixtures import backend_fixture, system_fixture


def pack(value):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    return {'status':'observed', 'value':{'encoding':'gzip-json-v1', 'bytes':len(raw),
        'sha256':hashlib.sha256(raw).hexdigest(),
        'data':base64.b64encode(gzip.compress(raw, mtime=0)).decode()}}


def scene_fixture():
    source = render.input_pattern()
    pixels = source * 12
    rows = [{'id':id, 'pixels':pixels, 'bitmap':pixels, 'png':pixels, 'repeat':pixels,
             'metrics':{'text':id, 'font':'13px fixture', 'width':20, 'left':0, 'right':20,
                        'ascent':12, 'descent':2} if id in ('latin','cjk','emoji') else None}
            for id in render.SCENES]
    gl = {}
    for api in ('webgl','webgl2'):
        limits = dict.fromkeys(render.GL_LIMITS + (render.GL2_LIMITS if api == 'webgl2' else ()), 16)
        for name in ('ALIASED_POINT_SIZE_RANGE','ALIASED_LINE_WIDTH_RANGE','MAX_VIEWPORT_DIMS'):
            limits[name] = [1,16]
        precision = {s:{p:{'rangeMin':14,'rangeMax':14,'precision':10} for p in render.PRECISIONS}
                     for s in ('VERTEX_SHADER','FRAGMENT_SHADER')}
        gl[api] = {'status':'observed','value':{
            'identity':{'vendor':'fixture-only', 'renderer':api + '-fixture',
                        'version':api, 'shadingLanguage':'fixture GLSL'},
            'attributes':{'alpha':False,'antialias':False,'preserveDrawingBuffer':True},
            'limits':limits, 'precision':precision, 'extensions':['fixture_extension'],
            'shaders':[{'mode':m,'status':'observed','pixels':source,'repeat':source} for m in ('mediump','highp')],
            'formats':[{'format':f,'pixels':[255,0,255,255]*256} for f in ('rgba8','rgb565','rgba4','rgb5a1')],
            'cross':{'origin':'bottom-left','pixels':render.flip_rows(source),'bitmap':source},
            'msaa':{'status':'observed','supported':[4,2],'samples':4,'actualSamples':4,
                    'pixels':[32,96,160,255]*256} if api == 'webgl2' else
                   {'status':'unavailable','reason':'WebGL1 has no explicit multisample resolve'}}}
    bgra = [source[i+(2,1,0,3)[k]] for i in range(0,len(source),4) for k in range(4)]
    return {'version':1,'width':64,'height':48,'source':source,
        'canvas':{'status':'observed','value':{'rows':rows,'glyphFileBinding':'not_verified'}},
        'webgl':gl, 'webgpu':{'status':'observed','value':{
            'identity':{'vendor':'different-fixture-adapter','architecture':'fixture','device':'0x1234',
                        'description':'unit test only','isFallbackAdapter':False},
            'features':[], 'rows':[{'format':f,'samples':n,'origin':'top-left',
                                   'pixels':source if f == 'rgba8unorm' else bgra}
                                  for f in ('rgba8unorm','bgra8unorm') for n in (1,4)]}}}


@lru_cache(maxsize=1)
def _template():
    chains = chain_template.__wrapped__()
    result = v2_observation()
    for scope, value in result.items():
        value['probeVersion'] = PROBE_VERSION
        if scope in ('window','iframe'):
            chains[scope]['taint'] = {'status':'not_collected'}
        raw = {'version':2, 'chain':chains[scope], 'scenes':scene_fixture(), 'gpuBackend':backend_fixture(scope),
               'integration':render_report() if scope in ('window','iframe') else
                             {'status':'not_applicable','reason':'DOM ownership tests run in window/iframe'}}
        value['render'] = pack(raw)
    result['window']['fontBackend'] = fonts.result([
        {'family':family,'text':text,'platformFonts':[{'familyName':'fixture-not-real',
            'postScriptName':'fixture-face','isCustomFont':False,'glyphCount':len(text)}]}
        for family in fonts.FAMILIES for text in fonts.TEXTS])
    result['window']['gpuSystem'] = system_fixture()
    return result


def observation():
    return deepcopy(_template())


@pytest.mark.parametrize('mode', ['intact', 'missing', 'sharp', 'quality', 'full'])
def test_codec_v2_source_errors_remain_admission_failures(mode):
    chains = codec_v2_template.__wrapped__(chain_template.__wrapped__())
    sample = observation()
    for scope in pool.SCOPES:
        raw = render.unpack(sample[scope]['render'])
        raw['chain'] = deepcopy(chains[scope])
        if scope in ('window', 'iframe'):
            raw['chain']['taint'] = {'status':'not_collected'}
        if scope == 'window' and mode != 'intact':
            row = raw['chain']['rows'][1]
            if mode == 'missing':
                row.pop('lossyQuality')
            else:
                item = {'sharp':row['exports'][1], 'quality':row['lossyQuality']['exports'][0],
                        'full':row['exports'][1]['fullQuality']}[mode]
                item.update(codec_export([0, 0, 0, 255] * 768, 'image/jpeg', 'html', item['quality']))
        sample[scope]['render'] = pack(raw)
    checked = render.assess_observation(sample)
    if mode == 'intact':
        assert checked['errors'] == []
    else:
        assert checked['errors']
        assert any('codec-source' in e or 'lossyQuality' in e for e in checked['errors'])


@pytest.mark.parametrize('lossy', [False, True])
def test_full_quality_webp_errors_remain_admission_failures(lossy):
    chains = codec_v2_template.__wrapped__(chain_template.__wrapped__())
    row = chains['window']['rows'][0]
    source = list(row['reference'])
    if not lossy:
        source[0] += 10
    item = row['exports'][2]['fullQuality']
    item.update(codec_export(source, 'image/webp', 'html', 0.5 if lossy else 1))
    item['quality'] = 1
    sample = observation()
    for scope in pool.SCOPES:
        raw = render.unpack(sample[scope]['render'])
        raw['chain'] = deepcopy(chains[scope])
        if scope in ('window', 'iframe'):
            raw['chain']['taint'] = {'status':'not_collected'}
        sample[scope]['render'] = pack(raw)
    checked = render.assess_observation(sample)
    assert any('/lossless-source:' in e for e in checked['errors'])
    assert any(('lossless WebP' if lossy else '/lossless-independent-source:') in e
               for e in checked['errors'])
    assert checked['codec_quality'] == []


def refresh_render(record, root, browser=None):
    root = Path(root)
    if browser is None:
        browser = pool.load_json(root / 'browser.json')
    (root / 'browser.json').write_text(json.dumps(browser), encoding='utf-8')
    checked = render.build_evidence(record['device']['host'], browser)
    (root / 'render.json').write_text(json.dumps(checked), encoding='utf-8')
    record['evidence'].update({name:{'path':name+'.json', 'sha256':pool.file_hash(root / (name+'.json'))}
                               for name in ('browser','render')})
    record['device']['surfaces'] = pool.stable_observation(browser['observations'][0])
    return seal(record)


def bundle(root):
    record = legacy_bundle(root)
    browser = pool.load_json(root / 'browser.json')
    browser.update(observations=[observation() for _ in range(3)], probe_sha256=probe_hash(),
                   browser_versions=['152.0.7977.82']*3, launch_args=['--fingerprint=off','--uxr-gpu-backend=native'])
    record.update(schema_version=2, qualification=deepcopy(pool.RENDER_QUALIFICATION))
    record['provenance'].update(probe_sha256=probe_hash(), browser_version='152.0.7977.82')
    return refresh_render(record, root, browser)


def test_full_fixture_checks_real_payload_contracts():
    sample = observation()
    checked = render.assess_observation(sample)
    assert checked['errors'] == []
    assert checked['canvas_comparisons'] > 100
    assert checked['canvas_skipped']  # Invented P3-unavailable fixture is not full coverage.
    assert render.scene_errors(scene_fixture()) == []
    assert pool.observation_errors(sample) == []


def test_v2_binds_gpu_fonts_probe_and_independent_render_evidence(tmp_path):
    record = pool.validate_record(bundle(tmp_path), tmp_path)
    selected = pool.select_record([record], record, 42)
    assert selected['status'] == 'compatible' and selected['record'] == record
    assert selected['record'] is not record and selected['overrides'] == []
    checked = pool.load_json(tmp_path / 'render.json')
    assert checked['gpu_inventory_sha256'] == pool.digest(record['device']['host']['gpu'])
    assert checked['font_file_to_glyph_binding'] == 'not_verified'
    assert 'data' not in record['device']['surfaces']['window']['render']['value']


def test_legacy_is_readable_but_cannot_claim_render_admission(tmp_path):
    record = pool.validate_record(legacy_bundle(tmp_path), tmp_path)
    selected = pool.select_record([record], record, 42)
    assert selected['status'] == 'native' and 'legacy' in str(selected['rejected'])


@pytest.mark.parametrize('fault', ['missing','hash','summary','provenance','downgrade'])
def test_admission_rejects_missing_or_forged_render_binding(tmp_path, fault):
    record = bundle(tmp_path)
    if fault == 'missing': del record['evidence']['render']
    elif fault == 'hash': record['evidence']['render']['sha256'] = 'a'*64
    elif fault == 'summary':
        data = pool.load_json(tmp_path / 'render.json'); data['gpu_inventory_sha256'] = 'a'*64
        (tmp_path / 'render.json').write_text(json.dumps(data))
        record['evidence']['render']['sha256'] = pool.file_hash(tmp_path / 'render.json')
    elif fault == 'provenance': record['provenance']['probe_sha256'] = 'a'*64
    else:
        record['schema_version'] = 1; record['qualification'] = deepcopy(pool.QUALIFICATION)
        del record['evidence']['render']
    with pytest.raises(ValueError): pool.validate_record(seal(record), tmp_path)


@pytest.mark.parametrize('field,value', [('encoding','json'), ('bytes',True), ('bytes',render.MAX_BYTES+1),
    ('sha256','a'*64), ('data','!not-base64!'), ('data','')])
def test_malformed_render_envelope(field, value):
    item = pack({'test':True}); item['value'][field] = value
    with pytest.raises(ValueError): render.unpack(item)


def test_decompression_rejects_trailing_members_and_duplicate_keys():
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                b'{"x":1e400}', b'{"x":-1e400}'):
        item = pack({}); item['value'].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            data=base64.b64encode(gzip.compress(raw,mtime=0)).decode())
        with pytest.raises(ValueError): render.unpack(item)
    item = pack({})
    item['value']['data'] = base64.b64encode(base64.b64decode(item['value']['data'])+gzip.compress(b'{}')).decode()
    with pytest.raises(ValueError): render.unpack(item)


@pytest.mark.parametrize('scope', pool.SCOPES)
def test_success_label_cannot_hide_missing_chain_or_scene(scope):
    sample = observation(); raw = render.unpack(sample[scope]['render'])
    raw['chain']['rows'][0]['padded'] = []
    sample[scope]['render'] = pack(raw)
    assert render.assess_observation(sample)['errors']
    raw['scenes']['canvas']['value']['rows'].pop()
    assert render.scene_errors(raw['scenes'])


@pytest.mark.parametrize('fault', ['shader','precision','format','orientation','msaa','gpu_format','fonts'])
def test_scene_matrix_faults_are_not_admitted(fault):
    sample = scene_fixture(); gl = sample['webgl']['webgl2']['value']
    if fault == 'shader': gl['shaders'][0]['repeat'] = []
    elif fault == 'precision': gl['precision']['VERTEX_SHADER'].pop('LOW_INT')
    elif fault == 'format': gl['formats'][0]['pixels'] = [0]*1024
    elif fault == 'orientation': gl['cross']['pixels'] = sample['source']
    elif fault == 'msaa': gl['msaa']['actualSamples'] = 1
    elif fault == 'gpu_format': sample['webgpu']['value']['rows'][2]['pixels'] = sample['source']
    else: sample['canvas']['value']['glyphFileBinding'] = 'verified'
    assert render.scene_errors(sample)


def test_no_artificial_uniqueness_or_universal_gpu_vendor_requirement():
    # Different API/context adapters are valid. The correlated observations, not
    # a renderer-name heuristic or forced per-profile hash rotation, bind them.
    sample = observation()
    sample['worker']['webgl']['value']['vendor'] = 'legitimate-other-adapter'
    assert pool.observation_errors(sample) == []
    assert pool.stable_observation(sample) == pool.stable_observation(deepcopy(sample))


def test_packaged_probe_hash_includes_every_render_asset():
    source = probe_source()
    assert probe_hash() == hashlib.sha256(source.encode()).hexdigest()
    assert len(ASSETS) == 5
    for name in ('canvasChainProbe','chromixRenderProbe','chromixSceneProbe','chromixDeviceProbe','chromixGpuBackendProbe'):
        assert name in source


def test_checked_summary_cache_does_not_trust_hash_or_share_mutable_results():
    sample = observation()
    first = render.assess_observation(sample)
    first['errors'].append('caller mutation')
    assert render.assess_observation(sample)['errors'] == []
    # Reuse the claimed digest but change the envelope bytes after cache fill.
    sample['window']['render']['value']['data'] = pack({'forged':True})['value']['data']
    assert render.assess_observation(sample)['errors']


@pytest.mark.parametrize('fault', ['missing','family','file','custom','count','face'])
def test_platform_glyph_faces_cannot_be_invented_from_widths(fault):
    item = observation()['window']['fontBackend']
    if fault == 'missing': item['value']['samples'].pop()
    elif fault == 'family': item['value']['samples'][0]['family'] = 'unknown'
    elif fault == 'file': item['value']['fileBinding'] = 'verified'
    elif fault == 'custom': item['value']['samples'][0]['platformFonts'][0]['isCustomFont'] = True
    elif fault == 'count': item['value']['samples'][0]['platformFonts'][0]['glyphCount'] = 0
    else: item['value']['samples'][0]['platformFonts'] = []
    assert fonts.font_errors(item)


@pytest.mark.parametrize('asynchronous', [False, True])
@pytest.mark.parametrize('mismatch', [False, True])
def test_cdp_font_collection_closes_session_and_removes_nodes(asynchronous, mismatch):
    import asyncio
    from types import SimpleNamespace
    samples = observation()['window']['fontBackend']['value']['samples']
    trace = []
    def evaluate(script):
        trace.append(script)
        return [{k:v for k,v in s.items() if k != 'platformFonts'} for s in samples]
    def send(method, params=None):
        if method == 'DOM.getDocument': return {'root':{'nodeId':1}}
        if method == 'DOM.querySelectorAll': return {'nodeIds':list(range(19 if mismatch else 20))}
        if method == 'CSS.getPlatformFontsForNode': return {'fonts':samples[params['nodeId']]['platformFonts']}
        return {}
    session = SimpleNamespace(send=send, detach=lambda:trace.append('detach'))
    context = SimpleNamespace(new_cdp_session=lambda _:session)
    page = SimpleNamespace(evaluate=evaluate)
    if asynchronous:
        async def evaluate_async(script): return evaluate(script)
        async def send_async(method, params=None): return send(method, params)
        async def detach(): trace.append('detach')
        async def create(_): return session
        page.evaluate, session.send, session.detach, context.new_cdp_session = evaluate_async,send_async,detach,create
        invoke = lambda:asyncio.run(fonts.collect_async(context,page))
    else: invoke = lambda:fonts.collect(context,page)
    if mismatch:
        with pytest.raises(ValueError, match='node count'): invoke()
    else:
        assert fonts.font_errors(invoke()) == []
    assert trace[-2:] == ['detach',fonts.FONT_CLEANUP]

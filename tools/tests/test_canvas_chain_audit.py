"""Offline fixtures validate the audit, not a browser or physical device."""
import base64
from copy import deepcopy
from io import BytesIO
import importlib.util
from pathlib import Path

import pytest

Image = pytest.importorskip('PIL.Image')
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('canvas_chain_audit', ROOT / 'tools/canvas_chain_audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def encoded(pixels, mime='image/png', size=(32, 24)):
    image = Image.frombytes('RGBA', size, bytes(pixels))
    if mime == 'image/jpeg':
        backdrop = Image.new('RGB', size)
        backdrop.paste(image, mask=image.getchannel('A'))
        image = backdrop
    buffer = BytesIO()
    # The passing validator fixture avoids chroma subsampling; live probes use
    # the browser's native encoder, whose quality bounds are reported separately.
    image.save(buffer, format=audit.FORMATS[mime], quality=92, subsampling=0, lossless=True)
    return base64.b64encode(buffer.getvalue()).decode('ascii')


def row(kind, alpha):
    ref = audit.input_pixels(alpha)
    exports = []
    for mime in audit.FORMATS:
        payload = encoded(ref, mime)
        decoded = audit.decode(payload, mime)['rgba']
        exports.append({'type':mime, 'bytes':payload, 'repeat':True,
                        'urlMatches':True if kind == 'html' else None,
                        'decoded':decoded, 'decodedSrgb':decoded,
                        'decodedNoPremultiply':decoded})
    return {'id':f'{kind}/srgb/{str(alpha).lower()}', 'kind':kind, 'alpha':alpha,
            'colorSpace':'srgb', 'width':32, 'height':24,
            'attributes':{'alpha':alpha, 'colorSpace':'srgb'}, 'input':audit.input_pixels(),
            'reference':ref, 'srgb':ref, 'direct':ref, 'noConversion':ref,
            'premultiply':{mode:ref for mode in ('none', 'premultiply', 'default')},
            'float16':{'status':'observed', 'typed':True, 'colorSpace':'srgb',
                       'pixels':[v / 255 for v in ref], 'inputReadback':ref},
            'crop':audit.region(ref, 3, 2, 7, 6), 'padded':audit.region(ref, -2, -2, 36, 28),
            'cropMatches':True, 'paddingMatches':True, 'sourceStable':True, 'finalRead':ref,
            'invalidRead':'IndexSizeError', 'fallback':'image/png', 'exports':exports,
            'transfer':{'pixels':ref, 'cleared':[0, 0, 0, 0 if alpha else 255] * (32 * 24)}
                       if kind == 'offscreen' else None}


@pytest.fixture(scope='module')
def template():
    result = {}
    for scope in audit.launch.pool.SCOPES:
        kinds = ('html', 'offscreen') if scope in ('window', 'iframe') else ('offscreen',)
        result[scope] = {'version':1, 'errors':[], 'rows':[row(k, a) for k in kinds for a in (True, False)],
                         'unavailable':[{'id':f'{k}/display-p3/{str(a).lower()}',
                                         'reason':'offline fixture: P3 unavailable'} for k in kinds for a in (True, False)],
                         'zeroBlob':'IndexSizeError'}
        result[scope]['edges'] = [{'id':f'{k}/{h}/{str(e).lower()}',
                                  'pixels':audit.region([48, 96, 160, 255] * 768, -2, -2, 36, 28)}
                                 for k in kinds for h in ('fresh', 'full', 'crop') for e in (False, True)]
        if scope in ('window', 'iframe'):
            result[scope].update(zeroURL='data:,', zeroCallback=True,
                                taint=[{'kind':k, 'read':'SecurityError', 'blob':'SecurityError',
                                        'url':'SecurityError' if k == 'html' else None} for k in kinds])
    return result


def test_valid_fixture_is_not_full_coverage(template):
    data = deepcopy(template)
    result = audit.evaluate(data)
    assert data == template
    assert result['errors'] == []
    assert len(result['skipped']) == 14
    assert result['comparisons']


@pytest.mark.parametrize('field,value', [
    ('reference', [0] * 3072), ('input', [0] * 3072), ('direct', [0] * 3072), ('finalRead', []),
    ('crop', []), ('padded', []), ('sourceStable', False), ('cropMatches', False),
    ('paddingMatches', False), ('fallback', 'image/jpeg'), ('invalidRead', None),
    ('attributes', {'alpha':False, 'colorSpace':'srgb'}), ('premultiply', {}),
    ('float16', {'status':'observed', 'typed':True, 'colorSpace':'srgb', 'pixels':[float('nan')] * 3072}),
    ('float16', {}), ('width', 31), ('alpha', 1), ('exports', []),
])
def test_mutated_row_rejected(template, field, value):
    data = deepcopy(template)
    data['window']['rows'][0][field] = value
    assert audit.evaluate(data)['errors']


@pytest.mark.parametrize('field,value', [('bytes', '!'), ('repeat', False), ('urlMatches', False),
                                        ('decoded', []), ('decodedSrgb', [0] * 3072),
                                        ('decodedNoPremultiply', [0] * 3072)])
def test_bad_export_rejected(template, field, value):
    data = deepcopy(template)
    data['window']['rows'][0]['exports'][0][field] = value
    assert audit.evaluate(data)['errors']


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'taint', 'zero', 'required-absent',
                                     'unknown-absent', 'duplicate-absent', 'probe-error', 'malformed'])
def test_incomplete_evidence_rejected(template, mutation):
    data = deepcopy(template)
    scope = data['window']
    if mutation == 'missing':
        scope['rows'].pop()
    elif mutation == 'duplicate':
        scope['rows'].append(deepcopy(scope['rows'][0]))
    elif mutation == 'taint':
        scope['taint'][0]['read'] = None
    elif mutation == 'zero':
        scope['zeroBlob'] = None
    elif mutation == 'required-absent':
        scope['unavailable'].append({'id':scope['rows'].pop()['id'], 'reason':'missing'})
    elif mutation == 'unknown-absent':
        scope['unavailable'].append({'id':'unknown/display-p3/true', 'reason':'missing'})
    elif mutation == 'duplicate-absent':
        scope['unavailable'].append(deepcopy(scope['unavailable'][0]))
    elif mutation == 'probe-error':
        scope['errors'].append({'name':'Error'})
    else:
        data['window'] = None
    assert audit.evaluate(data)['errors']


def test_cross_context_and_restart_signature(template):
    data = deepcopy(template)
    assert audit.cross_context_errors(data) == []
    before = audit.signature(data)
    data['iframe']['rows'][0]['reference'][0] += 1
    assert audit.cross_context_errors(data)
    assert before != audit.signature(data)


@pytest.mark.parametrize('missing', [True, False])
def test_options_history_edges(template, missing):
    data = deepcopy(template)
    if missing:
        data['window']['edges'].pop()
    else:
        data['window']['edges'][0]['pixels'][0] = 255
    assert audit.evaluate(data)['errors']


@pytest.mark.parametrize('mime', list(audit.FORMATS))
def test_independent_codec_validation(mime):
    data = audit.input_pixels()
    payload = encoded(data, mime)
    result = audit.decode(payload, mime)
    assert len(result['sha256']) == 64
    assert audit.compare(result['rgba'], data, lossy=mime != 'image/png', jpeg=mime == 'image/jpeg')['pass']
    wrong = 'image/jpeg' if mime == 'image/png' else 'image/png'
    with pytest.raises(ValueError):
        audit.decode(payload, wrong)


@pytest.mark.parametrize('value', ['', '!!!', 'A' * 1400001, None], ids=['empty', 'malformed', 'oversize', 'null'])
def test_bad_base64(value):
    with pytest.raises(ValueError):
        audit.decode(value, 'image/png')


def test_bad_dimensions():
    with pytest.raises(ValueError, match='dimensions'):
        audit.decode(encoded([0] * 16, size=(2, 2)), 'image/png')


def test_compare_premultiplication_and_limits():
    assert audit.compare([255, 20, 40, 0] * 768, [0] * 3072)['pass']
    assert audit.compare([100, 50, 20, 128] * 768, [50, 25, 10, 255] * 768)['pass'] is False
    assert audit.compare([100, 50, 20, 255] * 768, [100, 50, 20, 255] * 768)['pass']
    assert not audit.compare([100, 50, 20, 255] * 768, [140, 50, 20, 255] * 768, lossy=True)['pass']
    with pytest.raises(ValueError):
        audit.compare([True] * 3072, [0] * 3072)


def test_bridge_gate_precedes_endpoint_and_connection():
    patch = next((ROOT / 'patches').glob('0069-*')).read_text(encoding='utf-8')
    start = patch.index('+CanvasBridgeClient* CanvasBridgeClient::Get()')
    get = patch[start:patch.index('+CanvasBridgeClient::CanvasBridgeClient(', start)]
    assert get.index('config.Get("uxr-synthetic-device-tests") != "true"') < get.index('ParseEndpoint(')
    assert get.index('return nullptr;') < get.index('new CanvasBridgeClient(') < get.index('WaitUntilReady()')


def codec_export(reference, mime, kind, quality):
    image = Image.frombytes('RGBA', (32, 24), bytes(reference))
    if mime == 'image/jpeg':
        backdrop = Image.new('RGB', image.size)
        backdrop.paste(image, mask=image.getchannel('A'))
        image = backdrop
    buffer = BytesIO()
    image.save(buffer, format=audit.FORMATS[mime], quality=round(quality * 100),
               subsampling=0 if quality == 1 else 2, lossless=quality == 1, method=3)
    payload = base64.b64encode(buffer.getvalue()).decode('ascii')
    decoded = audit.decode(payload, mime)['rgba']
    return {'type':mime, 'quality':quality, 'bytes':payload, 'repeat':True,
            'urlMatches':True if kind == 'html' else None, 'decoded':decoded,
            'decodedSrgb':decoded, 'decodedNoPremultiply':decoded}


@pytest.fixture(scope='module')
def codec_v2_template(template):
    from chromix._canvas_chain import quality_pixels
    data = deepcopy(template)
    for scope in data.values():
        scope['version'] = 2
        for sample in scope['rows']:
            kind, alpha = sample['kind'], sample['alpha']
            for item in sample['exports']:
                item['quality'] = 0.92
                if item['type'] != 'image/png':
                    item.update(codec_export(sample['reference'], item['type'], kind, 0.92))
                    item['fullQuality'] = codec_export(sample['reference'], item['type'], kind, 1)
            reference = quality_pixels(alpha)
            sample['lossyQuality'] = {'input':quality_pixels(), 'reference':reference,
                'srgb':reference, 'finalRead':reference, 'attributes':sample['attributes'],
                'exports':[codec_export(reference, mime, kind, 0.92) for mime in ('image/jpeg', 'image/webp')]}
    return data


def test_subsampled_sharp_source_requires_codec_reference(codec_v2_template):
    data = deepcopy(codec_v2_template)
    result = audit.evaluate(data)
    assert result['errors'] == []
    assert data == codec_v2_template
    opaque = data['window']['rows'][1]
    for item in opaque['exports'][1:]:
        assert not audit.compare(item['decoded'], opaque['reference'], lossy=True)['pass']
    assert any(c.get('category') == 'codec-source' for c in result['comparisons'])
    assert all(c['max_bound'] == 36 and c['mean_bound'] == 7 for c in result['comparisons']
               if c.get('category') == 'codec-source')
    assert all(c['max_bound'] == 2 and c['mean_bound'] == 0.6 for c in result['comparisons']
               if c['path'].endswith('/independent-srgb'))


@pytest.mark.parametrize('mutation', ['quality-missing', 'quality-input', 'quality-source', 'quality-final',
    'quality-exports', 'quality-attributes', 'full-missing', 'full-type', 'full-quality', 'full-repeat',
    'full-url', 'sharp-quality', 'sharp-source-substitution', 'quality-source-substitution',
    'full-source-substitution', 'sharp-decoder-corruption', 'quality-decoder-corruption', 'full-decoder-corruption'])
def test_codec_v2_evidence_is_mandatory(codec_v2_template, mutation):
    data = deepcopy(codec_v2_template)
    sample = data['window']['rows'][1]
    quality = sample['lossyQuality']
    sharp = sample['exports'][1]
    full = sharp['fullQuality']
    if mutation == 'quality-missing':
        sample.pop('lossyQuality')
    elif mutation.startswith('quality-') and mutation.split('-', 1)[1] in ('input', 'source', 'final', 'exports', 'attributes'):
        field = {'source':'reference', 'final':'finalRead'}.get(mutation[8:], mutation[8:])
        quality[field] = []
    elif mutation == 'full-missing':
        sharp.pop('fullQuality')
    elif mutation.startswith('full-') and mutation[5:] in ('type', 'quality', 'repeat', 'url'):
        field = {'url':'urlMatches'}.get(mutation[5:], mutation[5:])
        full[field] = None
    elif mutation == 'sharp-quality':
        sharp['quality'] = 1
    else:
        name = mutation.split('-')[0]
        item = {'sharp':sharp, 'quality':quality['exports'][0], 'full':full}[name]
        if mutation.endswith('source-substitution'):
            item.update(codec_export([0, 0, 0, 255] * 768, 'image/jpeg', 'html', item['quality']))
        else:
            item['decodedSrgb'] = [255, 255, 255, 255] * 768
    errors = audit.evaluate(data)['errors']
    assert errors and any(not error.endswith(': codec-quality mismatch') for error in errors)


def webp_chunk(name, payload):
    return name + len(payload).to_bytes(4, 'little') + payload + b'\x00' * (len(payload) & 1)


def webp_riff(chunks):
    payload = b'WEBP' + b''.join(webp_chunk(name, data) for name, data in chunks)
    return b'RIFF' + len(payload).to_bytes(4, 'little') + payload


def lossless_chunks(alpha=True):
    item = codec_export(audit.input_pixels(alpha), 'image/webp', 'html', 1)
    raw = base64.b64decode(item['bytes'])
    assert raw[12:16] == b'VP8L'
    return [(b'VP8L', raw[20:20 + int.from_bytes(raw[16:20], 'little')])]


def extended_lossless_chunks(alpha=True):
    from PIL import ImageCms
    icc = ImageCms.ImageCmsProfile(ImageCms.createProfile('sRGB')).tobytes()
    header = bytes([0x20 | (0x10 if alpha else 0)]) + b'\x00' * 3
    header += (31).to_bytes(3, 'little') + (23).to_bytes(3, 'little')
    return [(b'VP8X', header), (b'ICCP', icc), *lossless_chunks(alpha)]


@pytest.mark.parametrize('extended', [False, True])
@pytest.mark.parametrize('alpha', [False, True])
def test_full_quality_webp_lossless_container(extended, alpha):
    from chromix._canvas_chain import decode
    raw = webp_riff(extended_lossless_chunks(alpha) if extended else lossless_chunks(alpha))
    checked = decode(base64.b64encode(raw).decode('ascii'), 'image/webp', lossless_webp=True)
    assert checked['lossless_webp']['container'] == ('VP8X' if extended else 'VP8L')
    assert checked['lossless_webp']['alpha'] is alpha
    assert audit.compare(checked['rgba'], audit.input_pixels(alpha))['pass']


@pytest.mark.parametrize('mutation', ['riff', 'webp', 'size-small', 'size-large', 'trailing',
    'truncated-header', 'huge-chunk', 'truncated-payload', 'bad-padding', 'duplicate-vp8l',
    'duplicate-vp8x', 'lossy', 'alpha-chunk', 'animation', 'unknown', 'missing-vp8l',
    'vp8l-signature', 'vp8l-version', 'vp8l-width', 'vp8l-height', 'vp8l-short',
    'vp8x-size', 'vp8x-reserved', 'vp8x-reserved-bytes', 'vp8x-animation', 'vp8x-width',
    'vp8x-height', 'alpha-flags', 'metadata-flags', 'metadata-empty', 'metadata-order',
    'vp8x-order', 'metadata-without-vp8x', 'too-many-chunks'])
def test_full_quality_webp_rejects_malformed_structure(mutation):
    from chromix._canvas_chain import webp_lossless_structure
    chunks = extended_lossless_chunks()
    if mutation in ('riff', 'webp', 'size-small', 'size-large', 'trailing', 'truncated-header',
                    'huge-chunk', 'truncated-payload', 'bad-padding'):
        raw = bytearray(webp_riff(chunks))
        if mutation == 'riff': raw[:4] = b'RIFX'
        elif mutation == 'webp': raw[8:12] = b'WAVE'
        elif mutation == 'size-small': raw[4:8] = (len(raw) - 10).to_bytes(4, 'little')
        elif mutation == 'size-large': raw[4:8] = (len(raw)).to_bytes(4, 'little')
        elif mutation == 'trailing': raw.extend(b'x')
        elif mutation == 'truncated-header': raw = bytearray(webp_riff(chunks) + b'VP8')
        elif mutation == 'huge-chunk': raw[16:20] = (0xffffffff).to_bytes(4, 'little')
        elif mutation == 'truncated-payload': raw = raw[:-2]
        else:
            raw = bytearray(webp_riff(chunks + [(b'XMP ', b'x')]))
            raw[-1] = 1
    else:
        if mutation == 'duplicate-vp8l': chunks.append(chunks[-1])
        elif mutation == 'duplicate-vp8x': chunks.insert(1, chunks[0])
        elif mutation in ('lossy', 'alpha-chunk', 'animation', 'unknown'):
            chunks.append(({'lossy':b'VP8 ', 'alpha-chunk':b'ALPH', 'animation':b'ANIM', 'unknown':b'FAKE'}[mutation], b'x'))
        elif mutation == 'missing-vp8l': chunks.pop()
        elif mutation.startswith('vp8l-'):
            payload = bytearray(chunks[-1][1])
            if mutation == 'vp8l-signature': payload[0] = 0
            elif mutation == 'vp8l-version': payload[4] |= 0x20
            elif mutation == 'vp8l-width': payload[1] ^= 1
            elif mutation == 'vp8l-height': payload[3] ^= 1
            else: payload = payload[:5]
            chunks[-1] = (b'VP8L', bytes(payload))
        elif mutation.startswith('vp8x-') and mutation != 'vp8x-order' or mutation == 'alpha-flags':
            payload = bytearray(chunks[0][1])
            if mutation == 'vp8x-size': payload.append(0)
            elif mutation == 'vp8x-reserved': payload[0] |= 0x80
            elif mutation == 'vp8x-reserved-bytes': payload[1] = 1
            elif mutation == 'vp8x-animation': payload[0] |= 2
            elif mutation == 'vp8x-width': payload[4] ^= 1
            elif mutation == 'vp8x-height': payload[7] ^= 1
            else: payload[0] ^= 0x10
            chunks[0] = (b'VP8X', bytes(payload))
        elif mutation == 'metadata-flags': chunks.pop(1)
        elif mutation == 'metadata-empty': chunks[1] = (b'ICCP', b'')
        elif mutation == 'metadata-order': chunks[1], chunks[2] = chunks[2], chunks[1]
        elif mutation == 'vp8x-order': chunks[0], chunks[1] = chunks[1], chunks[0]
        elif mutation == 'metadata-without-vp8x': chunks.pop(0)
        else: chunks.extend([(b'EXIF', b'x'), (b'XMP ', b'x'), (b'VP8L', b'x')])
        raw = webp_riff(chunks)
    with pytest.raises(ValueError, match='lossless WebP'):
        webp_lossless_structure(bytes(raw))


def test_full_quality_webp_checks_entropy_not_only_container():
    from chromix._canvas_chain import decode
    chunks = lossless_chunks()
    chunks[0] = (b'VP8L', chunks[0][1][:5] + b'\x00')
    with pytest.raises((ValueError, OSError)):
        decode(base64.b64encode(webp_riff(chunks)).decode('ascii'), 'image/webp', lossless_webp=True)


def test_full_quality_webp_rejects_coherent_low_quality(codec_v2_template):
    data = deepcopy(codec_v2_template)
    sample = data['window']['rows'][0]
    item = sample['exports'][2]['fullQuality']
    item.update(codec_export(sample['reference'], 'image/webp', 'html', 0.5))
    item['quality'] = 1
    assert audit.compare(item['decoded'], sample['reference'], lossy=True)['pass']
    assert not audit.compare(item['decoded'], sample['reference'])['pass']
    result = audit.evaluate(data, check_cross_context=False)
    assert any('/lossless-source:' in e for e in result['errors'])
    assert any('lossless WebP' in e for e in result['errors'])


def test_full_quality_webp_rejects_wrong_lossless_source(codec_v2_template):
    data = deepcopy(codec_v2_template)
    sample = data['window']['rows'][1]
    changed = list(sample['reference'])
    changed[0] += 10
    item = sample['exports'][2]['fullQuality']
    item.update(codec_export(changed, 'image/webp', 'html', 1))
    assert audit.compare(item['decoded'], sample['reference'], lossy=True)['pass']
    result = audit.evaluate(data, check_cross_context=False)
    assert any('/lossless-source:' in e for e in result['errors'])
    assert any('/lossless-independent-source:' in e for e in result['errors'])


def test_legacy_codec_quality_failure_not_reclassified(codec_v2_template):
    data = deepcopy(codec_v2_template)
    for scope in data.values():
        scope['version'] = 1
    assert any(error.endswith(': codec-quality mismatch') for error in audit.evaluate(data)['errors'])


@pytest.fixture(scope='module')
def codec_v3_template(codec_v2_template):
    data = deepcopy(codec_v2_template)
    for scope in data.values():
        scope['version'] = 3
        for sample in scope['rows']:
            items = [*sample['exports'], *sample['lossyQuality']['exports'],
                     *(item['fullQuality'] for item in sample['exports'][1:])]
            for item in items:
                url = 'data:' + item['type'] + ';base64,' + item['bytes'] if sample['kind'] == 'html' else None
                item.update(repeatBytes=item['bytes'], dataURL=url, repeatDataURL=url,
                            urlRepeat=True if url else None, urlBlobMatches=True if url else None)
    return data


def test_raw_export_evidence_passes_without_mutation(codec_v3_template):
    data = deepcopy(codec_v3_template)
    assert audit.evaluate(data)['errors'] == []
    assert data == codec_v3_template


@pytest.mark.parametrize('group', ['sharp', 'full', 'quality'])
@pytest.mark.parametrize('field,value', [
    ('repeatBytes', None), ('repeatBytes', 'YQ=='), ('dataURL', None),
    ('dataURL', 'data:image/png;base64,YQ=='), ('repeatDataURL', 'data:image/jpeg;base64,YQ=='),
    ('urlRepeat', False), ('urlRepeat', 1), ('urlBlobMatches', False), ('urlMatches', False),
])
def test_raw_exports_cannot_trust_reported_flags(codec_v3_template, group, field, value):
    data = deepcopy(codec_v3_template)
    sample = data['window']['rows'][1]
    item = {'sharp':sample['exports'][1], 'full':sample['exports'][1]['fullQuality'],
            'quality':sample['lossyQuality']['exports'][0]}[group]
    item[field] = value
    assert audit.evaluate(data, check_cross_context=False)['errors']


def test_dataurl_repeat_and_blob_mismatch_are_distinct(codec_v3_template):
    from chromix._canvas_chain import export_evidence_errors
    item = deepcopy(codec_v3_template['window']['rows'][1]['exports'][0])
    # Different bytes can decode to identical pixels and must still fail.
    image = Image.frombytes('RGBA', (32, 24), bytes(audit.input_pixels(False)))
    buffer = BytesIO()
    image.save(buffer, format='PNG', compress_level=0)
    alternate = base64.b64encode(buffer.getvalue()).decode('ascii')
    assert alternate != item['bytes']
    assert audit.decode(alternate, 'image/png')['rgba'] == item['decoded']
    item.update(dataURL='data:image/png;base64,' + alternate,
                repeatDataURL='data:image/png;base64,' + alternate,
                urlRepeat=True, urlBlobMatches=False, urlMatches=False)
    errors = export_evidence_errors(item, 'html', raw_payloads=True)
    assert 'DataURL/Blob payload mismatch' in errors
    assert 'DataURL repeat payload mismatch' not in errors
    item.update(dataURL='data:image/png;base64,' + item['bytes'],
                urlRepeat=False, urlBlobMatches=True)
    errors = export_evidence_errors(item, 'html', raw_payloads=True)
    assert 'DataURL repeat payload mismatch' in errors
    assert 'DataURL/Blob payload mismatch' not in errors


def test_offscreen_raw_evidence_requires_blob_repeat_and_null_urls(codec_v3_template):
    from chromix._canvas_chain import export_evidence_errors
    item = deepcopy(codec_v3_template['worker']['rows'][0]['exports'][0])
    assert export_evidence_errors(item, 'offscreen', raw_payloads=True) == []
    item['urlRepeat'] = True
    assert export_evidence_errors(item, 'offscreen', raw_payloads=True)
    item['urlRepeat'] = None
    del item['repeatBytes']
    assert export_evidence_errors(item, 'offscreen', raw_payloads=True)


def test_native_smoke_does_not_enable_synthetic_paths():
    from test_fingerprint_smoke import smoke, scenario
    for mode in ('native', 'on', 'off'):
        args = smoke.browser_args(scenario(mode), 'http://127.0.0.1:9876', False)
        assert ('--uxr-synthetic-device-tests=true' in args) == (mode == 'on')

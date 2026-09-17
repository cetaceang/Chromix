"""Shared independent Canvas codec/pixel checks for audits and measured admission."""
from __future__ import annotations
import base64
import hashlib
from io import BytesIO

SCOPES = ('window', 'iframe', 'worker', 'shared_worker', 'service_worker')
FORMATS = {'image/png':'PNG', 'image/jpeg':'JPEG', 'image/webp':'WEBP'}
WIDTH, HEIGHT = 32, 24
COLORS = ((48, 96, 160, 255), (160, 80, 48, 128),
          (40, 200, 100, 64), (200, 30, 160, 0))


def input_pixels(alpha=True):
    return [channel for _ in range(HEIGHT) for x in range(WIDTH)
            for channel in (*COLORS[x // 8][:3], COLORS[x // 8][3] if alpha else 255)]


def quality_pixels(alpha=True):
    row = []
    for x in range(WIDTH):
        position = max(0, min(3, (x - 4) / 8))
        left = int(position)
        right, fraction = min(3, left + 1), position - left
        row.extend(int(COLORS[left][k] * (1 - fraction) + COLORS[right][k] * fraction + 0.5)
                   if k != 3 or alpha else 255 for k in range(4))
    return row * HEIGHT


def encoded_reference(reference, mime):
    from PIL import Image
    image = Image.frombytes('RGBA', (WIDTH, HEIGHT), bytes(reference))
    if mime == 'image/jpeg':
        backdrop = Image.new('RGB', image.size)
        backdrop.paste(image, mask=image.getchannel('A'))
        image = backdrop
    buffer = BytesIO()
    # Encode source channels in their native space; ICC conversion follows decoding.
    image.save(buffer, format=FORMATS[mime], quality=92, subsampling=2, lossless=False, method=3)
    with Image.open(BytesIO(buffer.getvalue())) as decoded:
        return list(decoded.convert('RGBA').tobytes())


def region(reference, x, y, width, height):
    result = []
    for row in range(y, y + height):
        for col in range(x, x + width):
            offset = (row * WIDTH + col) * 4
            result.extend(reference[offset:offset + 4] if 0 <= row < HEIGHT and 0 <= col < WIDTH else [0] * 4)
    return result


def pixels(value, *, floating=False):
    import math
    return (isinstance(value, list) and len(value) == WIDTH * HEIGHT * 4 and
            all(type(v) in (int, float) and math.isfinite(v) if floating
                else type(v) is int and 0 <= v <= 255 for v in value))


def compare(actual, expected, *, lossy=False, jpeg=False):
    if not pixels(actual) or not pixels(expected):
        raise ValueError('invalid RGBA pixel array')
    differences = []
    alpha_error = 0
    for i in range(0, len(actual), 4):
        a, b = actual[i + 3] / 255, expected[i + 3] / 255
        alpha_error = max(alpha_error, abs(actual[i + 3] - (255 if jpeg else expected[i + 3])))
        # Compare visible premultiplied color, not undefined RGB under alpha=0.
        differences.extend(abs(actual[i + k] * a - expected[i + k] * b) for k in range(3))
    maximum, mean = max(differences), sum(differences) / len(differences)
    bound, average = (36, 7) if lossy else (2, 0.6)
    return {'pass':maximum <= bound and mean <= average and alpha_error <= 1,
            'max':maximum, 'mean':mean, 'alpha_max':alpha_error,
            'max_bound':bound, 'mean_bound':average}


def webp_lossless_structure(raw):
    if (not 20 <= len(raw) <= 1024 * 1024 or raw[:4] != b'RIFF' or raw[8:12] != b'WEBP' or
            int.from_bytes(raw[4:8], 'little') != len(raw) - 8):
        raise ValueError('invalid lossless WebP RIFF envelope')
    chunks = {}
    offset = 12
    while offset < len(raw):
        if len(chunks) == 5 or offset + 8 > len(raw):
            raise ValueError('invalid lossless WebP chunk count/header')
        name = raw[offset:offset + 4]
        size = int.from_bytes(raw[offset + 4:offset + 8], 'little')
        end = offset + 8 + size
        if end + (size & 1) > len(raw) or (size & 1 and raw[end] != 0):
            raise ValueError('invalid lossless WebP chunk extent/padding')
        # Canvas exports are static: no lossy, animation or unknown chunks.
        if name not in (b'VP8X', b'ICCP', b'VP8L', b'EXIF', b'XMP ') or name in chunks:
            raise ValueError('invalid lossless WebP chunk type/duplicate')
        chunks[name] = raw[offset + 8:end]
        offset = end + (size & 1)
    payload = chunks.get(b'VP8L', b'')
    if len(payload) < 6 or payload[0] != 0x2f:
        raise ValueError('missing lossless WebP VP8L bitstream')
    header = int.from_bytes(payload[1:5], 'little')
    width, height = (header & 0x3fff) + 1, ((header >> 14) & 0x3fff) + 1
    alpha = bool(header & (1 << 28))
    if header >> 29 or (width, height) != (WIDTH, HEIGHT):
        raise ValueError('invalid lossless WebP version/dimensions')
    names = list(chunks)
    if b'VP8X' in chunks:
        extended = chunks[b'VP8X']
        if (names[0] != b'VP8X' or len(extended) != 10 or extended[0] & ~0x3c or
                extended[1:4] != b'\x00\x00\x00' or
                int.from_bytes(extended[4:7], 'little') + 1 != width or
                int.from_bytes(extended[7:10], 'little') + 1 != height):
            raise ValueError('invalid lossless WebP VP8X header')
        flags = extended[0]
        if bool(flags & 0x10) != alpha:
            raise ValueError('inconsistent lossless WebP alpha flags')
        for name, flag in ((b'ICCP', 0x20), (b'EXIF', 0x08), (b'XMP ', 0x04)):
            if bool(flags & flag) != (name in chunks) or (name in chunks and not chunks[name]):
                raise ValueError('inconsistent lossless WebP metadata flags')
            if name in chunks and ((name == b'ICCP') != (names.index(name) < names.index(b'VP8L'))):
                raise ValueError('invalid lossless WebP metadata order')
    elif names != [b'VP8L']:
        raise ValueError('lossless WebP metadata requires VP8X')
    return {'container':'VP8X' if b'VP8X' in chunks else 'VP8L',
            'chunks':[name.decode('ascii') for name in names], 'alpha':alpha}


def decode(encoded, mime, *, lossless_webp=False):
    from PIL import Image, ImageCms
    if not isinstance(encoded, str) or not encoded or len(encoded) > 1400000:
        raise ValueError('invalid encoded image text')
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > 1024 * 1024:
        raise ValueError('invalid encoded image size')
    structure = None
    if lossless_webp:
        if mime != 'image/webp':
            raise ValueError('lossless WebP check requires WebP MIME')
        structure = webp_lossless_structure(raw)
    with Image.open(BytesIO(raw)) as image:
        if image.format != FORMATS[mime] or image.size != (WIDTH, HEIGHT):
            raise ValueError('encoded format or dimensions mismatch')
        image.load()
        rgba = image.convert('RGBA')
        icc = image.info.get('icc_profile')
        if icc:
            rgb = ImageCms.profileToProfile(image.convert('RGB'), ImageCms.ImageCmsProfile(BytesIO(icc)),
                                           ImageCms.createProfile('sRGB'), outputMode='RGB')
            converted = rgb.convert('RGBA')
            converted.putalpha(rgba.getchannel('A'))
        else:
            converted = rgba
        return {'rgba':list(rgba.tobytes()), 'srgb':list(converted.tobytes()),
                'icc':bool(icc), 'sha256':hashlib.sha256(raw).hexdigest(),
                **({'lossless_webp':structure} if structure is not None else {})}


def evaluate(observation, *, require_taint=True, check_cross_context=True):
    errors, comparisons, skipped = [], [], []
    if not isinstance(observation, dict):
        return {'errors':['observation must be an object'], 'comparisons':[], 'skipped':[]}
    for scope in SCOPES:
        value = observation.get(scope, {})
        try:
            if type(value.get('version')) is not int or value['version'] not in (1, 2) or value.get('errors') != []:
                raise ValueError('probe failed: ' + str(value.get('errors')))
            codec_v2 = value['version'] == 2
            kinds = ('html', 'offscreen') if scope in ('window', 'iframe') else ('offscreen',)
            expected = {f'{kind}/{space}/{str(alpha).lower()}' for kind in kinds
                        for space in ('srgb', 'display-p3') for alpha in (True, False)}
            seen = set()
            for absent in value.get('unavailable', []):
                if absent.get('id') not in expected or '/display-p3/' not in absent['id'] or not absent.get('reason'):
                    raise ValueError('required capability unavailable')
                if absent['id'] in seen:
                    raise ValueError('duplicate unavailable row')
                seen.add(absent['id'])
                skipped.append({'scope':scope, **absent})
            for row in value.get('rows', []):
                key = row['id']
                if key in seen or key != f"{row['kind']}/{row['colorSpace']}/{str(row['alpha']).lower()}":
                    raise ValueError('duplicate or inconsistent row')
                seen.add(key)
                label = scope + '/' + key
                if row.get('width') != WIDTH or row.get('height') != HEIGHT or type(row.get('alpha')) is not bool:
                    raise ValueError(label + ': dimensions/alpha mismatch')
                reference = row['reference']
                if not pixels(reference) or not pixels(row['srgb']):
                    raise ValueError(label + ': invalid reference')
                if row.get('input') != input_pixels():
                    raise ValueError(label + ': input pattern mismatch')
                attrs = row.get('attributes', {})
                if attrs.get('alpha') is not row['alpha'] or attrs.get('colorSpace') != row['colorSpace']:
                    raise ValueError(label + ': actual context attributes mismatch')
                for field in ('cropMatches', 'paddingMatches', 'sourceStable'):
                    if row.get(field) is not True:
                        errors.append(label + ': ' + field)
                for field, rect in (('crop', (3, 2, 7, 6)), ('padded', (-2, -2, WIDTH + 4, HEIGHT + 4))):
                    if row.get(field) != region(reference, *rect):
                        errors.append(label + ': ' + field + ' evidence mismatch')
                if row.get('finalRead') != reference:
                    errors.append(label + ': source changed after export')
                if row.get('invalidRead') != 'IndexSizeError' or row.get('fallback') != 'image/png':
                    errors.append(label + ': exception/MIME fallback mismatch')
                alphas = [reference[(x * 4) + 3] for x in (0, 8, 16, 24)]
                if alphas != ([255, 128, 64, 0] if row['alpha'] else [255] * 4):
                    errors.append(label + ': alpha contract mismatch')
                def check(name, actual, wanted, *, category=None, **options):
                    result = compare(actual, wanted, **options)
                    category = category or ('codec-quality' if options.get('lossy') else 'pixel-consistency')
                    comparisons.append({'path':label + '/' + name, 'category':category, **result})
                    if not result['pass']:
                        errors.append(label + '/' + name + ': ' + category + ' mismatch')
                check('input-readback', reference, input_pixels(row['alpha']))
                if row['colorSpace'] == 'srgb':
                    check('same-space-read', row['srgb'], reference)
                check('direct-bitmap', row['direct'], reference)
                check('no-color-conversion', row['noConversion'], reference)
                if set(row['premultiply']) != {'none', 'premultiply', 'default'}:
                    raise ValueError('missing premultiply cases')
                for mode, actual in row['premultiply'].items():
                    check('premultiply/' + mode, actual, reference)
                floating = row['float16']
                if floating.get('status') == 'observed':
                    check('float16-input', floating.get('inputReadback'), input_pixels(row['alpha']))
                    if floating.get('typed') is not True or floating.get('colorSpace') != row['colorSpace'] or not pixels(floating.get('pixels'), floating=True):
                        raise ValueError('float16 metadata/values invalid')
                    if any(v < 0 or v > 1 for v in floating['pixels']):
                        errors.append(label + ': out-of-range float16 for bounded input')
                    elif not compare([round(v * 255) for v in floating['pixels']], reference)['pass']:
                        errors.append(label + ': float16/uint8 mismatch')
                elif floating.get('status') == 'unavailable' and floating.get('reason'):
                    skipped.append({'scope':label, 'reason':floating['reason']})
                else:
                    raise ValueError('missing float16 probe')
                encoded = row['exports']
                if [item.get('type') for item in encoded] != list(FORMATS):
                    raise ValueError('missing codec matrix')
                for item in encoded:
                    mime = item['type']
                    if item.get('repeat') is not True or (row['kind'] == 'html' and item.get('urlMatches') is not True):
                        errors.append(label + '/' + mime + ': unstable or mismatched exports')
                    jpeg = mime == 'image/jpeg'
                    if codec_v2 and item.get('quality') != 0.92:
                        raise ValueError(label + ': incorrect export quality')
                    if codec_v2 and mime != 'image/png':
                        check(mime + '/independent-encode', item['decoded'], encoded_reference(reference, mime),
                              lossy=True, category='codec-source')
                    else:
                        check(mime + '/browser', item['decodedSrgb'] if jpeg else item['decoded'],
                              row['srgb'] if jpeg else reference, lossy=mime != 'image/png', jpeg=jpeg)
                    check(mime + '/premultiply-decode', item['decodedNoPremultiply'], item['decoded'])
                    independent = decode(item['bytes'], mime)
                    check(mime + '/independent-srgb', independent['srgb'], item['decodedSrgb'],
                          lossy=not codec_v2 and mime != 'image/png')
                    if mime == 'image/png':
                        check(mime + '/independent-raw', independent['rgba'], reference)
                    comparisons.append({'path':label + '/' + mime + '/independent-decode', 'pass':True,
                                        **{k:v for k,v in independent.items() if k not in ('rgba','srgb')}})
                if codec_v2:
                    quality = row['lossyQuality']
                    if quality.get('input') != quality_pixels():
                        raise ValueError(label + ': quality input pattern mismatch')
                    if quality.get('attributes') != attrs:
                        raise ValueError(label + ': quality context attributes mismatch')
                    if quality.get('finalRead') != quality.get('reference'):
                        raise ValueError(label + ': quality source changed after export')
                    check('quality/input-readback', quality['reference'], quality_pixels(row['alpha']))
                    if not pixels(quality['srgb']):
                        raise ValueError(label + ': invalid quality sRGB readback')
                    if row['colorSpace'] == 'srgb':
                        check('quality/same-space-read', quality['srgb'], quality['reference'])
                    if [item.get('type') for item in quality['exports']] != ['image/jpeg', 'image/webp']:
                        raise ValueError(label + ': missing quality codec matrix')
                    for name, items, ref, srgb, expected_quality in (
                            ('full-quality', [item['fullQuality'] for item in encoded[1:]], reference, row['srgb'], 1),
                            ('quality', quality['exports'], quality['reference'], quality['srgb'], 0.92)):
                        for mime, item in zip(('image/jpeg', 'image/webp'), items):
                            if (item.get('type') != mime or item.get('quality') != expected_quality or
                                    item.get('repeat') is not True or
                                    (row['kind'] == 'html' and item.get('urlMatches') is not True)):
                                raise ValueError(label + ': invalid ' + name + ' export')
                            jpeg = mime == 'image/jpeg'
                            check(name + '/' + mime + '/browser', item['decodedSrgb'] if jpeg else item['decoded'],
                                  srgb if jpeg else ref, lossy=True, jpeg=jpeg, category='codec-source')
                            check(name + '/' + mime + '/premultiply-decode', item['decodedNoPremultiply'], item['decoded'])
                            lossless_webp = name == 'full-quality' and mime == 'image/webp'
                            if lossless_webp:
                                check(name + '/' + mime + '/lossless-source', item['decoded'], ref)
                            independent = decode(item['bytes'], mime, lossless_webp=lossless_webp)
                            check(name + '/' + mime + '/independent-srgb', independent['srgb'], item['decodedSrgb'])
                            if lossless_webp:
                                check(name + '/' + mime + '/lossless-independent-source', independent['rgba'], ref)
                                comparisons.append({'path':label + '/' + name + '/' + mime + '/lossless-bitstream',
                                                    'pass':True, **independent['lossless_webp']})
                if row['kind'] == 'offscreen':
                    check('transfer', row['transfer']['pixels'], reference)
                    clear = row['transfer']['cleared']
                    expected_clear = [0,0,0,0 if row['alpha'] else 255] * (WIDTH * HEIGHT)
                    if clear != expected_clear:
                        errors.append(label + ': transfer did not reset backing store')
            if seen != expected:
                raise ValueError('incomplete row matrix')
            edge_ids = {f'{k}/{h}/{str(e).lower()}' for k in kinds
                        for h in ('fresh', 'full', 'crop') for e in (False, True)}
            edges = value.get('edges')
            if not isinstance(edges, list) or len(edges) != len(edge_ids) or {e['id'] for e in edges} != edge_ids:
                raise ValueError('incomplete options/history edge matrix')
            edge_pixels = region([48, 96, 160, 255] * (WIDTH * HEIGHT), -2, -2, WIDTH + 4, HEIGHT + 4)
            for edge in edges:
                if edge.get('pixels') != edge_pixels:
                    errors.append(scope + '/edge/' + edge['id'] + ': out-of-bounds read mismatch')
            if value.get('zeroBlob') != 'IndexSizeError':
                raise ValueError('zero OffscreenCanvas exception mismatch')
            if scope in ('window', 'iframe'):
                if value.get('zeroURL') != 'data:,' or value.get('zeroCallback') is not True:
                    raise ValueError('zero HTMLCanvas behavior mismatch')
                if not require_taint:
                    if value.get('taint') != {'status':'not_collected'}:
                        raise ValueError('embedded probe must label taint as not collected')
                    continue
                taint = value.get('taint')
                if not isinstance(taint, list) or [r.get('kind') for r in taint] != ['html','offscreen']:
                    raise ValueError('missing taint tests')
                for row in taint:
                    if row.get('read') != 'SecurityError' or row.get('blob') != 'SecurityError' or (
                            row['kind'] == 'html' and row.get('url') != 'SecurityError'):
                        raise ValueError('tainted canvas did not reject read/export')
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
            errors.append(scope + ': ' + str(error))
    if check_cross_context:
        errors.extend(cross_context_errors(observation))
    return {'errors':errors, 'comparisons':comparisons, 'skipped':skipped}


def cross_context_errors(observation):
    errors = []
    baseline = observation.get('window', {})
    if not isinstance(baseline, dict):
        return errors
    rows = baseline.get('rows', [])
    if not isinstance(rows, list):
        return errors
    reference = {r['id']:r for r in rows if isinstance(r, dict) and isinstance(r.get('id'), str)}
    for scope in SCOPES:
        if scope == 'window' or not isinstance(observation.get(scope), dict):
            continue
        rows = observation[scope].get('rows', [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('id'), str):
                continue
            key = row['id']
            if key not in reference:
                errors.append(scope + '/' + key + ': capability differs from window')
                continue
            # Compare the same canvas kind and options, including encoded bytes.
            for field in ('reference', 'srgb', 'direct', 'premultiply', 'noConversion', 'float16', 'exports', 'lossyQuality', 'transfer'):
                if row.get(field) != reference[key].get(field):
                    errors.append(scope + '/' + key + '/' + field + ': cross-context mismatch')
        absent = observation[scope].get('unavailable', [])
        if isinstance(absent, list):
            for row in absent:
                if isinstance(row, dict) and isinstance(row.get('id'), str) and row['id'] in reference:
                    errors.append(scope + '/' + row['id'] + ': capability differs from window')
    return errors

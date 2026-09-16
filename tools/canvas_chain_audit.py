#!/usr/bin/env python3
"""Canvas API/codec integration audit. Requires Playwright and Pillow with LittleCMS."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.server import ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sdk/python'))
from chromix import _device_launch as launch

PROBE = Path(__file__).resolve().parents[1] / 'sdk/python/chromix/canvas_chain_probe.js'
from chromix._canvas_chain import (FORMATS, WIDTH, HEIGHT, COLORS, input_pixels,
    region, pixels, compare, decode, evaluate, cross_context_errors)


class Handler(launch.ProbeHandler):
    def send_header(self, name, value):
        if name.lower() == 'content-security-policy':
            value = "default-src 'self'; img-src 'self' " + self.server.taint_origin
        super().send_header(name, value)

    def do_GET(self):
        if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
            self.send_error(403)
            return
        if self.path == '/probe.js':
            body = (PROBE.read_text(encoding='utf-8') + '\n' +
                    'globalThis.chromixDeviceProbe = canvasChainProbe;\n' +
                    'globalThis.canvasTaintURL = ' + json.dumps(self.server.taint_origin + '/test.png') + ';').encode()
            mime = 'text/javascript'
        elif self.path == '/test.png':
            body, mime = self.server.png, 'image/png'
        else:
            super().do_GET()
            return
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def server(taint_origin=''):
    from PIL import Image
    data = BytesIO()
    Image.new('RGBA', (2, 2), (32, 64, 128, 255)).save(data, format='PNG')
    instance = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    instance.daemon_threads = True
    instance.taint_origin, instance.png = taint_origin, data.getvalue()
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{instance.server_port}'
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def collect_live(context, origin):
    # This page serves only Canvas probes, not the device font/GPU bundle.
    page = context.new_page()
    try:
        page.goto(origin, wait_until='load', timeout=launch.DEFAULT_TIMEOUT)
        observation = {'window':page.evaluate(launch.PROBE_EVAL)}
        observation['iframe'] = page.frame(url=origin + '/frame').evaluate(launch.PROBE_EVAL)
        for scope in launch.pool.SCOPES[2:]:
            observation[scope] = page.evaluate(launch.WORKER_EVAL, scope)
        return observation
    finally:
        page.close()


def signature(observation):
    # All operations are fixed inputs; salted identities and elapsed timings are absent.
    return launch.pool.digest(observation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--headed', action='store_true')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new file')
    report = {'schema_version':1, 'collected_at':datetime.now(timezone.utc).isoformat(),
              'runs':[], 'errors':[], 'qualification':'capability audit, not matching-patch build attestation'}
    try:
        from PIL import features, __version__ as pillow_version
        from playwright.sync_api import sync_playwright
        if not features.check('littlecms2') or not features.check('webp'):
            raise ValueError('Pillow LittleCMS and WebP decoders are required')
        report['browser_sha256'] = launch.pool.file_hash(args.browser)
        report['probe_sha256'] = launch.pool.file_hash(PROBE)
        report['decoders'] = {'pillow':pillow_version, 'littlecms2':features.version('littlecms2'),
                              'webp':features.version('webp')}
        report['launch_args'] = launch.NATIVE_ARGS
        with tempfile.TemporaryDirectory(prefix='chromix-canvas-') as profiles, server() as other, server(other) as origin, sync_playwright() as pw:
            for profile in ('a','a','b'):
                context = pw.chromium.launch_persistent_context(str(Path(profiles) / profile),
                    executable_path=str(args.browser.resolve()), headless=not args.headed,
                    no_viewport=True, chromium_sandbox=True, args=launch.NATIVE_ARGS)
                try:
                    report['browser_version'] = context.browser.version
                    observation = collect_live(context, origin)
                    result = evaluate(observation)
                    report['runs'].append({'profile':profile, 'observation':observation, **result})
                    report['errors'].extend(result['errors'])
                finally:
                    context.close()
            signatures = [signature(run['observation']) for run in report['runs']]
            if len(set(signatures)) != 1:
                report['errors'].append('canvas results changed across restart/profiles')
            report['signatures'] = signatures
        if launch.pool.file_hash(args.browser) != report['browser_sha256']:
            report['errors'].append('browser executable changed')
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    report['skipped_count'] = sum(len(run['skipped']) for run in report['runs'])
    report['status'] = 'failed' if report['errors'] else 'incomplete' if report['skipped_count'] else 'passed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=True)
        stream.write('\n')
    print(json.dumps({'status':report['status'], 'error_count':len(report['errors']),
                      'first_errors':report['errors'][:12], 'output':str(args.output)}))
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())

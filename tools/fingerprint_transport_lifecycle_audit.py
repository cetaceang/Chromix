#!/usr/bin/env python3
"""Owned TLS 1.3 ticket resumption and HTTP/2 connection reuse observations."""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlsplit

from fingerprint_protocols import compare
from fingerprint_transport_audit import endpoint, IDENTITY, launch, header_errors

PHASES = ('initial', 'reuse', 'goaway', 'resumed', 'reuse_after')
PROBE = """async context => {
  const phases=[];
  for (const phase of ['reuse','goaway','resumed','reuse_after']) {
    const path='/echo?context='+context+'&phase='+phase+(phase==='goaway'?'&close=1':'');
    const response=await fetch(path,{cache:'no-store'});
    if (!response.ok) throw new Error('fixture status '+response.status);
    phases.push({phase,wire:await response.json()});
  }
  return phases;
}"""


def valid_settings(rows):
    return (isinstance(rows, list) and 0 < len(rows) <= 128 and
            all(isinstance(row, list) and len(row) == 2 and type(row[0]) is int and
                0 <= row[0] <= 65535 and type(row[1]) is int and 0 <= row[1] <= 2**32 - 1 for row in rows) and
            len({row[0] for row in rows}) == len(rows))


def assess(report):
    try:
        return _assess(report)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as error:
        return ['malformed transport lifecycle evidence: ' + str(error)], []


def _assess(report):
    errors = list(report.get('errors', []))
    connections = report['connections']
    by_id = {c['id']: c for c in connections}
    if len(by_id) != len(connections) or any(type(i) is not int or i < 1 for i in by_id):
        errors.append('invalid or duplicate connection ids')
    hellos = report['client_hellos']
    runs = report['runs']
    if [r['context'] for r in runs] != [0, 1] or any(type(r['context']) is not int for r in runs):
        errors.append('two independent browser contexts were not observed')
    profiles = {'full': [], 'resumed': []}
    used = set()
    settings, orders = [], []
    for run in runs:
        phases = run['phases']
        if [p['phase'] for p in phases] != list(PHASES):
            errors.append('incomplete connection lifecycle')
            continue
        ids = [p['wire']['connection_id'] for p in phases]
        if any(type(i) is not int or i not in by_id for i in ids):
            errors.append('request references an unobserved connection')
            continue
        if not (ids[0] == ids[1] == ids[2] and ids[3] == ids[4] and ids[0] != ids[3]):
            errors.append('HTTP2 reuse / GOAWAY reconnect sequence failed')
        if used & set(ids):
            errors.append('browser contexts shared a transport connection')
        used.update(ids)
        for kind, connection_id, resumed in (('full', ids[0], False), ('resumed', ids[3], True)):
            c = by_id[connection_id]
            if c.get('alpn') != 'h2' or c.get('tls') != 'TLSv1.3' or c.get('session_reused') is not resumed:
                errors.append(kind + ': negotiated TLS13/H2 session state mismatch')
            candidates = [h for h in hellos if h.get('connection_id') == connection_id]
            if len(candidates) != 1:
                errors.append(kind + ': missing unique ClientHello/connection binding')
            else:
                h = candidates[0]
                if (41 in h['extensions']) is not resumed:
                    errors.append(kind + ': PSK offer does not match session state')
                profiles[kind].append(h)
            if not c.get('settings') or any(not valid_settings(rows) for rows in c['settings']):
                errors.append(kind + ': no HTTP2 peer SETTINGS')
            else:
                settings.append(c['settings'][0])
            streams = [r['stream'] for r in c['requests']]
            if (any(type(s) is not int or s < 1 or s % 2 != 1 for s in streams) or
                    len(set(streams)) != len(streams)):
                errors.append(kind + ': invalid or reused HTTP2 request stream')
        close = phases[2]['wire']
        for phase in phases:
            wire = phase['wire']
            headers = wire['headers']
            target = urlsplit(headers[':path'])
            query = {'context': [str(run['context'])], 'phase': [phase['phase']]}
            if phase['phase'] == 'goaway':
                query['close'] = ['1']
            if target.path != '/echo' or parse_qs(target.query) != query:
                errors.append('phase does not match observed request path')
            matches = [r for r in by_id[wire['connection_id']]['requests'] if dict(r['headers']) == headers]
            if len(matches) != 1:
                errors.append('response is not bound to one server-observed request')
                continue
            request = matches[0]
            order = [k for k, _ in request['headers'] if k.startswith(':')]
            if (request.get('pseudo_order') != order or len(order) != 4 or
                    set(order) != {':method', ':authority', ':scheme', ':path'} or
                    [k for k, _ in request['headers'][:4]] != order):
                errors.append('invalid HTTP2 pseudo-header order evidence')
            orders.append(order)
            if phase['phase'] == 'goaway' and by_id[close['connection_id']].get('goaway_stream') != request['stream']:
                errors.append('missing server GOAWAY for the closing request')
        identity = run['identity']
        wire = identity['wire']
        if (wire.get('connection_id') != ids[-1] or wire['headers'].get(':path') != '/echo' or
                len([r for r in by_id[ids[-1]]['requests'] if dict(r['headers']) == wire['headers']]) != 1):
            errors.append('identity response is not bound to the resumed connection')
        scope = {'identity': {'value': {'ua': identity['userAgent'], 'languages': identity['languages'],
                    'uaData': identity['userAgentData']}}, 'http': {'status': 'observed', 'value': identity['wire']}}
        errors.extend(header_errors(scope, require_hints=True))
    if settings and any(s != settings[0] for s in settings[1:]):
        errors.append('HTTP2 SETTINGS changed across fresh/resumed connections')
    if orders and any(o != orders[0] for o in orders[1:]):
        errors.append('HTTP2 pseudo-header order changed across fresh/resumed connections')
    comparisons = []
    for kind, values in profiles.items():
        if len(values) != 2:
            errors.append(kind + ': missing two independently observed handshakes')
        else:
            result = compare(*values)
            comparisons.append({'kind': kind, **result})
            if result['status'] != 'observed_match':
                errors.append(kind + ': TLS profile changed across browser contexts')
    return sorted(set(errors)), comparisons


def run(browser, headed=False):
    report = {'schema_version': 1, 'browser_sha256': launch.pool.file_hash(browser),
              'collected_at': datetime.now(timezone.utc).isoformat(), 'errors': [], 'runs': [],
              'client_hellos': [], 'connections': [], 'qualification': {
                  'kind': 'owned TLS endpoint; actual session state and H2 requests',
                  'proxy': 'not_tested', 'dns': 'not_tested', 'physical_network': 'not_attested',
                  'zero_rtt': 'not_tested', 'ticket_contents': 'not_recorded'}}
    try:
        from playwright.sync_api import sync_playwright
        with tempfile.TemporaryDirectory(prefix='chromix-tls-lifecycle-') as directory:
            with endpoint(Path(directory), tickets=True) as (server, origin), sync_playwright() as pw:
                args = [*launch.NATIVE_ARGS, '--ignore-certificate-errors-spki-list=' + server.spki]
                report['launch_args'] = args
                instance = pw.chromium.launch(executable_path=str(browser.resolve()), headless=not headed,
                    chromium_sandbox=True, args=args)
                try:
                    report['browser_version'] = instance.version
                    for i in range(2):
                        context = instance.new_context(no_viewport=True)
                        try:
                            page = context.new_page()
                            # Bind the full handshake before navigation can seed a PSK reconnect.
                            response = page.goto(origin + f'/echo?context={i}&phase=initial',
                                wait_until='load', timeout=30000)
                            if response is None or not response.ok:
                                raise RuntimeError('missing successful initial navigation response')
                            initial = {'phase': 'initial', 'wire': response.json()}
                            report['runs'].append({'context': i,
                                'phases': [initial, *page.evaluate(launch.bounded(PROBE), i)],
                                'identity': page.evaluate(launch.bounded(IDENTITY), None)})
                        finally:
                            context.close()
                finally:
                    instance.close()
            report['client_hellos'] = copy.deepcopy(server.hellos)
            report['connections'] = copy.deepcopy(server.connections)
            report['errors'].extend(server.handshake_errors)
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    if launch.pool.file_hash(browser) != report['browser_sha256']:
        report['errors'].append('browser executable changed')
    report['errors'], report['comparisons'] = assess(report)
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

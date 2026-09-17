#!/usr/bin/env python3
"""Reconcile missing release platforms after coalesced workflow completion events."""
from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

try:
    from . import release_browser as release
except ImportError:
    import release_browser as release

MAX_PAGES = 10
MAX_VERSION_LOOKUPS = 200


def requested_version(repo: str, event: dict, event_name: str, manual_version: str) -> str:
    if event_name == 'workflow_dispatch':
        if os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise ValueError('Release catch-up must run from main')
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', manual_version):
            raise ValueError('Invalid manual release version')
        return manual_version
    if event_name != 'workflow_run':
        raise ValueError('Unsupported release trigger')
    event_run = event['workflow_run']
    release.validate_run(event_run, repo)
    current = release.api(repo, f"actions/runs/{int(event_run['id'])}")
    if (not release.matches_run(current, repo, event_run['head_sha'])
            or current['name'] != event_run['name'] or current.get('event') != event_run['event']
            or int(current['id']) != int(event_run['id'])):
        raise ValueError('Triggering workflow run identity changed')
    # A coalesced wake-up remains useful even if its original attempt is now stale.
    version = release.source_version(repo, event_run['head_sha'], release.WORKFLOW_PLATFORMS[event_run['name']])
    if manual_version and manual_version != version:
        raise ValueError('Release version differs from the validated event source version')
    return version


def newest_workflow_runs(repo: str, workflow: str):
    current = None
    previous_id = None
    for page in range(1, MAX_PAGES + 1):
        result = release.api(repo, f'actions/workflows/{workflow}.yml/runs?branch=main&per_page=100&page={page}')
        batch = result['workflow_runs']
        for run in batch:
            identity = release.run_identity(run)
            if previous_id is not None and identity[0] > previous_id:
                raise ValueError('Workflow run listing is not newest-first; refusing incomplete discovery')
            if current is not None and identity[0] != previous_id:
                yield current
                current = None
            previous_id = identity[0]
            if not release.matches_run(run, repo, run.get('head_sha', '')) or run['name'] != workflow:
                continue
            # Resolve duplicate snapshots and attempts before accepting this run ID.
            if (current is None or identity > release.run_identity(current)
                    or (identity == release.run_identity(current)
                        and (run.get('status') != 'completed' or run.get('conclusion') != 'success'))):
                current = run
        if not batch or page * 100 >= result['total_count']:
            if current is not None:
                yield current
            return
    raise ValueError(f'Release discovery limit reached for {workflow}; no partial publication attempted')


def discover_runs(repo: str, version: str, *, include_build_only: bool = False) -> dict[str, dict]:
    versions = {}
    selected = {}
    for workflow in release.WORKFLOWS:
        platform = release.WORKFLOW_PLATFORMS[workflow]
        seen_shas = set()
        for run in newest_workflow_runs(repo, workflow):
            sha = run['head_sha']
            if sha in seen_shas:
                continue
            seen_shas.add(sha)
            if run.get('event') == 'workflow_dispatch' and not include_build_only:
                commit = run.get('head_commit')
                message = commit.get('message') if isinstance(commit, dict) else None
                if not isinstance(message, str) or '[skip ci]' in message.lower():
                    continue
            key = (sha, platform)
            if key not in versions:
                if len(versions) >= MAX_VERSION_LOOKUPS:
                    raise ValueError('Release source-version lookup limit reached; narrow the catch-up scope')
                versions[key] = release.source_version(repo, sha, platform)
            if (versions[key] == version and run.get('status') == 'completed'
                    and run.get('conclusion') == 'success'
                    and release.native_verification_passed(repo, run)):
                selected[workflow] = run
                break
    return selected


def published_slots(repo: str, tag: str, root: Path) -> set[str]:
    pages = json.loads(release.gh('api', '--paginate', '--slurp', f'repos/{repo}/releases?per_page=100'))
    current = next((item for page in pages for item in page if item['tag_name'] == tag), None)
    if not current or current.get('draft'):
        return set()
    destination = root / 'published-manifest'
    destination.mkdir()
    hashes = release.restore_release_manifest(repo, tag, current, destination)
    return set(hashes) & release.ASSETS


def reconcile(repo: str, version: str, *, include_build_only: bool = False) -> None:
    # Discover all platforms before downloads or writes, so bounds cannot yield a partial scan.
    runs = discover_runs(repo, version, include_build_only=include_build_only)
    tag = 'v' + version
    with tempfile.TemporaryDirectory(prefix='chromix-release-catch-up-') as directory:
        root = Path(directory)
        existing = published_slots(repo, tag, root)
        failures = []
        for name, run in runs.items():
            assets = {asset + '.zip' for asset in release.WORKFLOWS[name]}
            if assets <= existing:
                print(f'Preserved published platform: {name}')
                continue
            if not release.ready_run(repo, run):
                continue
            platform_root = root / name
            platform_root.mkdir()
            try:
                bundles = release.collect(repo, run, platform_root)
            except Exception as error:
                failure = f'{name}: {type(error).__name__}: {error}'
                failures.append(failure)
                print(f'Platform artifact collection failed: {failure}')
                continue
            release.publish(repo, run, tag, bundles, platform_root)
        missing = set(release.WORKFLOWS) - set(runs)
        if missing:
            print('Platforms with no eligible latest successful run: ' + ', '.join(sorted(missing)))
        if failures:
            raise RuntimeError('Platform artifact collection failed: ' + '; '.join(failures))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-ready', action='store_true')
    parser.add_argument('--version', default=os.environ.get('RELEASE_VERSION', ''))
    args = parser.parse_args(argv)
    repo = os.environ['GITHUB_REPOSITORY']
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    version = requested_version(repo, event, os.environ['GITHUB_EVENT_NAME'], args.version)
    if args.check_ready:
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
            output.write(f'ready=true\nversion={version}\n')
        return
    if os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch':
        reconcile(repo, version, include_build_only=True)
    else:
        reconcile(repo, version)


if __name__ == '__main__':
    main()

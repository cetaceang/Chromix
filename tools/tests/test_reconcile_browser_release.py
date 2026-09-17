"""Offline catch-up tests for coalesced platform completion events."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import reconcile_browser_release as reconcile
from tools import release_browser as release

REPO = 'owner/chromix'
VERSION = '152.0.7977.82'


def run(name, number, *, success=True, **changes):
    result = {'id': number, 'run_attempt': 1, 'name': name,
              'path': f'.github/workflows/{name}.yml', 'head_sha': f'{number:040x}',
              'head_branch': 'main', 'repository': {'full_name': REPO},
              'head_repository': {'full_name': REPO}, 'event': 'push',
              'status': 'completed', 'conclusion': 'success' if success else 'failure'}
    result.update(changes)
    return result


class ReconcileReleaseTest(unittest.TestCase):
    def setUp(self):
        self.runs = {name: run(name, 100 + n) for n, name in enumerate(release.WORKFLOWS)}
        self.listings = {name: [item] for name, item in self.runs.items()}
        self.current = {item['id']: item for item in self.runs.values()}
        self.api = self.enterContext(patch.object(release, 'api', side_effect=self.fake_api))
        self.source_version = release.source_version
        self.version = self.enterContext(patch.object(release, 'source_version', return_value=VERSION))
        self.gh = self.enterContext(patch.object(release, 'gh', side_effect=AssertionError('Unexpected GitHub call')))
        self.native = self.enterContext(patch.object(release, 'native_verification_passed', return_value=True))
        self.stdout = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))

    def fake_api(self, repo, path):
        self.assertEqual(repo, REPO)
        if path.startswith('actions/runs/'):
            return self.current[int(path.rsplit('/', 1)[1])]
        name = path.split('/')[2].removesuffix('.yml')
        self.assertIn(name, self.listings)
        page = int(path.rsplit('page=', 1)[1])
        items = self.listings[name]
        return {'workflow_runs': items[(page - 1) * 100:page * 100], 'total_count': len(items)}

    def run_main(self, event, event_name, *args, version=''):
        with tempfile.TemporaryDirectory() as directory:
            event_path, output = Path(directory) / 'event.json', Path(directory) / 'output'
            event_path.write_text(json.dumps(event))
            with patch.dict(os.environ, GITHUB_REPOSITORY=REPO, GITHUB_REF='refs/heads/main',
                            GITHUB_EVENT_NAME=event_name, GITHUB_EVENT_PATH=str(event_path),
                            GITHUB_OUTPUT=str(output), RELEASE_VERSION=version):
                reconcile.main(list(args))
            return output.read_text() if output.exists() else ''

    def test_all_platforms_are_discovered_across_source_commits(self):
        self.assertEqual(reconcile.discover_runs(REPO, VERSION), self.runs)
        self.assertEqual(len({item['head_sha'] for item in self.runs.values()}), 6)

    def test_arm64_build_without_native_acceptance_is_not_discovered(self):
        name = 'build-win-arm64-github'
        self.native.side_effect = lambda repo, item: item['name'] != name
        selected = reconcile.discover_runs(REPO, VERSION)
        self.assertEqual(set(selected), set(self.runs) - {name})
        self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION, include_build_only=True))

    def test_arm64_unverified_latest_blocks_same_sha_fallback(self):
        name = 'build-win-arm64-github'
        old = self.runs[name]
        newest = run(name, 999, head_sha=old['head_sha'])
        self.listings[name] = [newest, old]
        self.native.side_effect = lambda repo, item: item['id'] != newest['id']
        self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))
        earlier = run(name, 50)
        self.listings[name].append(earlier)
        self.assertEqual(reconcile.discover_runs(REPO, VERSION)[name], earlier)

    def test_unverified_arm64_does_not_block_other_missing_platforms(self):
        name = 'build-win-arm64-github'
        self.native.side_effect = lambda repo, item: item['name'] != name
        with patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', return_value={}), patch.object(release, 'publish') as publish:
            reconcile.reconcile(REPO, VERSION)
        self.assertEqual(publish.call_count, 4)
        self.assertNotIn(name, {call.args[1]['name'] for call in publish.call_args_list})
        self.assertIn('Platforms with no eligible latest successful run: ' + name, self.stdout.getvalue())

    def test_published_arm64_slot_is_preserved_without_artifact_download(self):
        existing = {'chromix-win-x64.zip', 'chromix-win-arm64.zip'}
        with patch.object(reconcile, 'published_slots', return_value=existing), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', return_value={}) as collect, \
                patch.object(release, 'publish') as publish:
            reconcile.reconcile(REPO, VERSION)
        for operation in (collect, publish):
            self.assertEqual(operation.call_count, 4)
            self.assertTrue(all(not call.args[1]['name'].startswith('build-win-')
                                for call in operation.call_args_list))

    def test_arm64_integrity_failure_does_not_publish_its_slot(self):
        name = 'build-win-arm64-github'
        self.runs = {name: self.runs[name], **self.runs}
        with patch.object(reconcile, 'discover_runs', return_value=self.runs), \
                patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', side_effect=[ValueError('Expected ARM64 PE'), {}, {}, {}, {}]), \
                patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(RuntimeError, name + '.*Expected ARM64 PE'):
                reconcile.reconcile(REPO, VERSION)
        self.assertEqual(publish.call_count, 4)
        self.assertNotIn(name, {call.args[1]['name'] for call in publish.call_args_list})

    def test_automatic_discovery_excludes_build_only_and_unknown_manual_commits(self):
        name = 'build-macos-x64'
        for head_commit in ({'message': 'Repair [skip ci]'}, {'message': 'Repair [SKIP CI]'},
                            {'message': None}, {'message': 123}, None, {}, 'bad', ['bad']):
            candidate = run(name, 999, event='workflow_dispatch', head_commit=head_commit)
            self.listings[name] = [candidate]
            with self.subTest(head_commit=head_commit):
                self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))
                self.assertEqual(reconcile.discover_runs(REPO, VERSION, include_build_only=True)[name], candidate)

    def test_build_only_latest_run_blocks_same_sha_fallback_in_automatic_discovery(self):
        name = 'build-macos-x64'
        old = self.runs[name]
        self.listings[name] = [run(name, 999, head_sha=old['head_sha'], event='workflow_dispatch',
                                  head_commit={'message': 'Repair [skip ci]'}), old]
        self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))

    def test_normal_manual_build_remains_eligible_for_automatic_discovery(self):
        name = 'build-macos-x64'
        candidate = run(name, 999, event='workflow_dispatch', head_commit={'message': 'Normal build'})
        self.listings[name] = [candidate]
        self.assertEqual(reconcile.discover_runs(REPO, VERSION)[name], candidate)

    def test_explicit_manual_release_includes_build_only_candidates(self):
        with patch.object(reconcile, 'reconcile') as publish:
            self.run_main({}, 'workflow_dispatch', version=VERSION)
        publish.assert_called_once_with(REPO, VERSION, include_build_only=True)

    def test_other_build_event_does_not_enable_build_only_candidates(self):
        name = 'build-macos-x64'
        self.listings[name] = [run(name, 999, event='workflow_dispatch', head_commit={'message': 'Repair [skip ci]'})]
        with patch.object(reconcile, 'published_slots', return_value=set()), \
                patch.object(release, 'ready_run', side_effect=lambda repo, candidate: candidate), \
                patch.object(release, 'collect', return_value={}) as collect, \
                patch.object(release, 'publish') as publish:
            self.run_main({'workflow_run': self.runs['build-linux-x64']}, 'workflow_run')
        self.assertNotIn(name, [call.args[1]['name'] for call in collect.call_args_list])
        self.assertNotIn(name, [call.args[1]['name'] for call in publish.call_args_list])

    def test_newer_other_sha_failure_or_running_run_does_not_hide_success(self):
        name = next(iter(self.runs))
        for status, conclusion in (('completed', 'failure'), ('in_progress', None), ('queued', None)):
            with self.subTest(status=status):
                self.listings[name] = [run(name, 999, status=status, conclusion=conclusion), self.runs[name]]
                self.assertEqual(reconcile.discover_runs(REPO, VERSION), self.runs)

    def test_failed_or_running_latest_same_sha_never_falls_back(self):
        name = next(iter(self.runs))
        sha = self.runs[name]['head_sha']
        for status, conclusion in (('completed', 'failure'), ('completed', 'cancelled'), ('in_progress', None)):
            with self.subTest(status=status, conclusion=conclusion):
                self.listings[name] = [run(name, 999, head_sha=sha, status=status, conclusion=conclusion),
                                       self.runs[name]]
                self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))

    def test_same_sha_failure_does_not_block_an_older_distinct_sha_success(self):
        name = next(iter(self.runs))
        older = run(name, 50)
        self.listings[name] = [run(name, 999, head_sha=self.runs[name]['head_sha'], success=False),
                               self.runs[name], older]
        self.assertEqual(reconcile.discover_runs(REPO, VERSION)[name], older)

    def test_newest_successful_run_at_same_sha_wins(self):
        name = next(iter(self.runs))
        latest = run(name, 999, head_sha=self.runs[name]['head_sha'])
        self.listings[name] = [latest, self.runs[name]]
        self.assertEqual(reconcile.discover_runs(REPO, VERSION)[name], latest)

    def test_newer_failed_attempt_blocks_same_run_success_in_either_snapshot_order(self):
        name = next(iter(self.runs))
        older = self.runs[name]
        latest = {**older, 'run_attempt': 2, 'conclusion': 'failure'}
        for items in ([older, latest], [latest, older]):
            with self.subTest(attempts=[item['run_attempt'] for item in items]):
                self.listings[name] = items
                self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))

    def test_newer_successful_attempt_wins_over_failed_snapshot(self):
        name = next(iter(self.runs))
        older = {**self.runs[name], 'conclusion': 'failure'}
        latest = {**self.runs[name], 'run_attempt': 2}
        for items in ([older, latest], [latest, older]):
            self.listings[name] = items
            self.assertEqual(reconcile.discover_runs(REPO, VERSION)[name], latest)

    def test_conflicting_snapshot_of_same_attempt_fails_closed(self):
        name = next(iter(self.runs))
        success = self.runs[name]
        pending = {**success, 'status': 'in_progress', 'conclusion': None}
        for items in ([success, pending], [pending, success]):
            self.listings[name] = items
            self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))

    def test_attempt_snapshots_straddling_pages_are_resolved_before_selection(self):
        name = next(iter(self.runs))
        sha = self.runs[name]['head_sha']
        invalid = [run(name, number, repository={'full_name': 'other/repo'}) for number in range(999, 900, -1)]
        self.listings[name] = invalid + [run(name, 900, head_sha=sha),
                                        run(name, 900, head_sha=sha, run_attempt=2, success=False)]
        self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))
        self.assertTrue(any('page=2' in call.args[1] for call in self.api.call_args_list))

    def test_same_sha_blocking_survives_page_boundary(self):
        name = next(iter(self.runs))
        sha = self.runs[name]['head_sha']
        self.listings[name] = [run(name, number, head_sha=sha, success=False) for number in range(999, 899, -1)]
        older = run(name, 50)
        self.listings[name] += [self.runs[name], older]
        self.assertEqual(reconcile.discover_runs(REPO, VERSION)[name], older)

    def test_newer_other_version_does_not_hide_requested_version(self):
        name = next(iter(self.runs))
        latest = run(name, 999)
        self.listings[name].insert(0, latest)
        self.version.side_effect = lambda repo, sha, platform: '153.0.0.1' if sha == latest['head_sha'] else VERSION
        self.assertEqual(reconcile.discover_runs(REPO, VERSION), self.runs)

    def test_source_version_cache_is_shared_only_within_sha_and_platform(self):
        sha = next(iter(self.runs.values()))['head_sha']
        for name in self.runs:
            self.listings[name] = [{**self.runs[name], 'head_sha': sha}]
        self.assertEqual(len(reconcile.discover_runs(REPO, VERSION)), 6)
        self.assertEqual(self.version.call_count, 3)
        self.assertEqual({call.args for call in self.version.call_args_list},
                         {(REPO, sha, platform) for platform in ('linux', 'macos', 'windows')})

    def test_same_sha_candidates_are_isolated_by_platform_version(self):
        sha = 'a' * 40
        linux_version = '153.0.8010.36'
        for name in self.runs:
            self.runs[name]['head_sha'] = sha
        self.version.side_effect = lambda repo, commit, platform: linux_version if platform == 'linux' else VERSION
        for version in (VERSION, linux_version):
            with self.subTest(version=version):
                self.version.reset_mock()
                selected = reconcile.discover_runs(REPO, version)
                expected = {name for name in self.runs if name.startswith('build-linux-') == (version == linux_version)}
                self.assertEqual(set(selected), expected)
                self.assertEqual({item['head_sha'] for item in selected.values()}, {sha})
                self.assertEqual(self.version.call_count, 3)

    def test_same_sha_platform_events_publish_only_their_version_group(self):
        linux_version = '153.0.8010.36'
        for candidate in self.runs.values():
            candidate['head_sha'] = 'a' * 40
        self.version.side_effect = lambda repo, sha, platform: linux_version if platform == 'linux' else VERSION
        for event_run in self.runs.values():
            version = linux_version if event_run['name'].startswith('build-linux-') else VERSION
            with self.subTest(workflow=event_run['name']), \
                    patch.object(reconcile, 'published_slots', return_value=set()), \
                    patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                    patch.object(release, 'collect', return_value={}), patch.object(release, 'publish') as publish:
                self.run_main({'workflow_run': event_run}, 'workflow_run', version=version)
                expected = {name for name in self.runs if name.startswith('build-linux-') == (version == linux_version)}
                self.assertEqual({call.args[1]['name'] for call in publish.call_args_list}, expected)
                self.assertTrue(all(call.args[2] == 'v' + version for call in publish.call_args_list))

    def test_event_readiness_and_queued_version_use_validated_platform(self):
        linux_version = '153.0.8010.36'
        self.version.side_effect = lambda repo, sha, platform: linux_version if platform == 'linux' else VERSION
        for event_run in self.runs.values():
            platform = release.WORKFLOW_PLATFORMS[event_run['name']]
            version = linux_version if platform == 'linux' else VERSION
            wrong_version = VERSION if platform == 'linux' else linux_version
            with self.subTest(workflow=event_run['name']):
                self.assertEqual(self.run_main({'workflow_run': event_run}, 'workflow_run', '--check-ready'),
                                 f'ready=true\nversion={version}\n')
                self.version.assert_called_with(REPO, event_run['head_sha'], platform)
                with self.assertRaisesRegex(ValueError, 'validated event source version'):
                    reconcile.requested_version(REPO, {'workflow_run': event_run}, 'workflow_run', wrong_version)

    def test_platform_lookup_bound_counts_same_sha_separately_before_writes(self):
        for candidate in self.runs.values():
            candidate['head_sha'] = 'a' * 40
        with patch.object(reconcile, 'MAX_VERSION_LOOKUPS', 1), \
                patch.object(reconcile, 'published_slots') as slots, patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(ValueError, 'lookup limit'):
                reconcile.reconcile(REPO, VERSION)
        self.version.assert_called_once_with(REPO, 'a' * 40, 'linux')
        slots.assert_not_called()
        publish.assert_not_called()

    def test_linux_version_error_blocks_discovery_and_readiness_before_writes(self):
        for error in (ValueError('Invalid Chromium version'),
                      subprocess.CalledProcessError(1, ['gh', 'api'], stderr='gh: Forbidden (HTTP 403)')):
            with self.subTest(error=type(error).__name__), \
                    patch.object(reconcile, 'published_slots') as slots, patch.object(release, 'collect') as collect, \
                    patch.object(release, 'publish') as publish:
                self.version.side_effect = error
                with self.assertRaises(type(error)):
                    reconcile.reconcile(REPO, VERSION)
                with self.assertRaises(type(error)):
                    self.run_main({'workflow_run': self.runs['build-linux-x64']}, 'workflow_run', '--check-ready')
                slots.assert_not_called()
                collect.assert_not_called()
                publish.assert_not_called()

    def configure_windows_migration(self, windows_version='153.0.8010.36', shared_version='153.0.8010.36'):
        sha = 'a' * 40
        for candidate in self.runs.values():
            candidate['head_sha'] = sha
        pins = {'CHROMIUM_VERSION': shared_version, 'CHROMIUM_LINUX_VERSION': '153.0.8010.36',
                'CHROMIUM_WINDOWS_VERSION': windows_version, 'CHROMIUM_MACOS_VERSION': VERSION}

        def source_contents(*args):
            self.assertEqual(args[0], 'api')
            self.assertEqual(args[2:], ('-H', 'Accept: application/vnd.github.raw+json'))
            filename = args[1].split('/contents/')[1].split('?ref=')[0]
            self.assertEqual(args[1], f'repos/{REPO}/contents/{filename}?ref={sha}')
            value = pins[filename]
            if isinstance(value, Exception):
                raise value
            return value

        self.gh.side_effect = source_contents
        self.version.side_effect = self.source_version
        return sha

    def test_same_sha_linux_windows153_lookup_cache_keeps_all_three_platforms_separate(self):
        sha = self.configure_windows_migration()
        for version in ('153.0.8010.36', VERSION):
            with self.subTest(version=version):
                self.gh.reset_mock()
                self.version.reset_mock()
                selected = reconcile.discover_runs(REPO, version)
                expected = {name for name in self.runs if name.startswith('build-macos-') == (version == VERSION)}
                self.assertEqual(set(selected), expected)
                self.assertEqual({candidate['head_sha'] for candidate in selected.values()}, {sha})
                self.assertEqual(self.version.call_count, 3)
                self.assertEqual({call.args for call in self.version.call_args_list},
                                 {(REPO, sha, platform) for platform in ('linux', 'macos', 'windows')})
                self.assertEqual(self.gh.call_count, 3)
                self.assertEqual({call.args[1] for call in self.gh.call_args_list},
                                 {f'repos/{REPO}/contents/{filename}?ref={sha}' for filename in
                                  ('CHROMIUM_LINUX_VERSION', 'CHROMIUM_WINDOWS_VERSION', 'CHROMIUM_MACOS_VERSION')})

    def test_same_sha_linux_windows153_events_publish_only_matching_version_slots(self):
        self.configure_windows_migration()
        for event_run in self.runs.values():
            version = VERSION if event_run['name'].startswith('build-macos-') else '153.0.8010.36'
            with self.subTest(workflow=event_run['name']), \
                    patch.object(reconcile, 'published_slots', return_value=set()), \
                    patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                    patch.object(release, 'collect', return_value={}) as collect, patch.object(release, 'publish') as publish:
                self.run_main({'workflow_run': event_run}, 'workflow_run', version=version)
                expected = {name for name in self.runs if name.startswith('build-macos-') == (version == VERSION)}
                for operation in (collect, publish):
                    self.assertEqual(operation.call_count, len(expected))
                    self.assertEqual({call.args[1]['name'] for call in operation.call_args_list}, expected)
                self.assertEqual({call.args[2] for call in publish.call_args_list}, {'v' + version})

    def test_windows153_readiness_rejects_queued_shared_version(self):
        sha = self.configure_windows_migration()
        for event_run in self.runs.values():
            platform = release.WORKFLOW_PLATFORMS[event_run['name']]
            version = VERSION if platform == 'macos' else '153.0.8010.36'
            wrong = '153.0.8010.36' if platform == 'macos' else VERSION
            with self.subTest(workflow=event_run['name']):
                self.assertEqual(self.run_main({'workflow_run': event_run}, 'workflow_run', '--check-ready'),
                                 f'ready=true\nversion={version}\n')
                self.version.assert_called_with(REPO, sha, platform)
                with self.assertRaisesRegex(ValueError, 'validated event source version'):
                    self.run_main({'workflow_run': event_run}, 'workflow_run', '--check-ready', version=wrong)

    def test_windows_lookup_counts_separately_even_when_linux_has_same_version(self):
        sha = self.configure_windows_migration()
        with patch.object(reconcile, 'MAX_VERSION_LOOKUPS', 2), \
                patch.object(reconcile, 'published_slots') as slots, patch.object(release, 'collect') as collect, \
                patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(ValueError, 'lookup limit'):
                reconcile.reconcile(REPO, '153.0.8010.36')
        self.assertEqual([call.args for call in self.version.call_args_list],
                         [(REPO, sha, 'linux'), (REPO, sha, 'macos')])
        slots.assert_not_called()
        collect.assert_not_called()
        publish.assert_not_called()

    def test_missing_windows_pin_preserves_legacy_discovery_only_on_exact_404(self):
        sha = self.configure_windows_migration(subprocess.CalledProcessError(
            1, ['gh', 'api'], stderr='gh: Not Found (HTTP 404)\n'), shared_version=VERSION)
        selected = reconcile.discover_runs(REPO, VERSION)
        self.assertEqual(set(selected), {name for name in self.runs if not name.startswith('build-linux-')})
        self.assertEqual(self.version.call_count, 3)
        self.assertEqual([call.args[1] for call in self.gh.call_args_list],
                         [f'repos/{REPO}/contents/{filename}?ref={sha}' for filename in
                          ('CHROMIUM_LINUX_VERSION', 'CHROMIUM_MACOS_VERSION', 'CHROMIUM_WINDOWS_VERSION', 'CHROMIUM_VERSION')])

    def test_windows_pin_errors_abort_discovery_and_readiness_without_fallback_or_writes(self):
        cases = [('', ValueError), ('153.0.8010.36-1.1', ValueError)]
        cases += [(subprocess.CalledProcessError(1, ['gh', 'api'], stderr=message), subprocess.CalledProcessError)
                  for message in ('gh: Forbidden (HTTP 403)', 'gh: API rate limit exceeded (HTTP 429)',
                                  'gh: Server Error (HTTP 500)', 'gh: Not Found (HTTP 404) extra')]
        for value, error_type in cases:
            with self.subTest(value=value), patch.object(reconcile, 'published_slots') as slots, \
                    patch.object(release, 'collect') as collect, patch.object(release, 'publish') as publish:
                sha = self.configure_windows_migration(value)
                self.gh.reset_mock()
                with self.assertRaises(error_type):
                    reconcile.reconcile(REPO, '153.0.8010.36')
                self.assertEqual(self.gh.call_count, 3)
                self.assertEqual(self.gh.call_args.args[1], f'repos/{REPO}/contents/CHROMIUM_WINDOWS_VERSION?ref={sha}')
                for workflow in ('build-win-x64-github', 'build-win-arm64-github'):
                    self.gh.reset_mock()
                    with self.assertRaises(error_type):
                        self.run_main({'workflow_run': self.runs[workflow]}, 'workflow_run', '--check-ready')
                    self.assertEqual(self.gh.call_count, 1)
                    self.assertIn('/contents/CHROMIUM_WINDOWS_VERSION?ref=', self.gh.call_args.args[1])
                slots.assert_not_called()
                collect.assert_not_called()
                publish.assert_not_called()

    def test_invalid_workflow_repository_does_not_publish(self):
        name = next(iter(self.runs))
        self.listings[name][0]['repository'] = {'full_name': 'other/repo'}
        self.assertNotIn(name, reconcile.discover_runs(REPO, VERSION))

    def test_invalid_newer_run_does_not_supersede_trusted_same_sha(self):
        name = next(iter(self.runs))
        self.listings[name].insert(0, run(name, 999, head_sha=self.runs[name]['head_sha'],
                                         repository={'full_name': 'other/repo'}, success=False))
        self.assertEqual(reconcile.discover_runs(REPO, VERSION), self.runs)

    def test_non_newest_first_listing_fails_before_writes(self):
        name = next(iter(self.runs))
        self.listings[name].append(run(name, 999))
        with patch.object(reconcile, 'published_slots') as slots, patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(ValueError, 'not newest-first'):
                reconcile.reconcile(REPO, VERSION)
            slots.assert_not_called()
            publish.assert_not_called()

    def test_page_bound_fails_before_any_publication_even_after_other_platform_found(self):
        name = list(self.runs)[1]
        self.listings[name] = [run(name, number, success=False) for number in range(999, 798, -1)]
        with patch.object(reconcile, 'MAX_PAGES', 2), patch.object(reconcile, 'published_slots') as slots, \
                patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(ValueError, 'discovery limit'):
                reconcile.reconcile(REPO, VERSION)
            slots.assert_not_called()
            publish.assert_not_called()
        self.assertFalse(any('page=3' in call.args[1] for call in self.api.call_args_list))

    def test_lookup_bound_fails_before_any_publication(self):
        with patch.object(reconcile, 'MAX_VERSION_LOOKUPS', 1), \
                patch.object(reconcile, 'published_slots') as slots, patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(ValueError, 'lookup limit'):
                reconcile.reconcile(REPO, VERSION)
            self.assertEqual(self.version.call_count, 1)
            slots.assert_not_called()
            publish.assert_not_called()

    def test_production_bounds_are_explicit(self):
        self.assertEqual(reconcile.MAX_PAGES, 10)
        self.assertEqual(reconcile.MAX_VERSION_LOOKUPS, 200)

    def test_surviving_event_publishes_all_five_missing_platforms_without_x64_collection(self):
        with patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item) as ready, \
                patch.object(release, 'collect', side_effect=lambda repo, item, root: {'fixture': root}) as collect, \
                patch.object(release, 'publish') as publish:
            reconcile.reconcile(REPO, VERSION)
        expected = set(self.runs) - {'build-win-x64-github'}
        for operation in (ready, collect, publish):
            self.assertEqual(operation.call_count, 5)
            self.assertEqual({call.args[1]['name'] for call in operation.call_args_list}, expected)
        self.assertTrue(all(call.args[2] == 'v' + VERSION for call in publish.call_args_list))
        self.assertEqual(len({call.args[1]['head_sha'] for call in publish.call_args_list}), 5)

    def test_finished_slots_preserved_and_stale_incoming_skipped(self):
        with patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', return_value=None), \
                patch.object(release, 'collect') as collect, patch.object(release, 'publish') as publish:
            reconcile.reconcile(REPO, VERSION)
        collect.assert_not_called()
        publish.assert_not_called()

    def test_local_collect_errors_allow_remaining_platforms_then_fail_aggregate(self):
        errors = [subprocess.CalledProcessError(1, ['gh', 'run', 'download']),
                  ValueError('Checksum mismatch'), zipfile.BadZipFile('Corrupt ZIP'),
                  FileNotFoundError('Missing artifact'), RuntimeError('Artifact expired')]
        first = next(iter(self.runs))
        for error in errors:
            with self.subTest(error=type(error).__name__), \
                    patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                    patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                    patch.object(release, 'collect', side_effect=[error, {}, {}, {}, {}]) as collect, \
                    patch.object(release, 'publish') as publish:
                with self.assertRaisesRegex(RuntimeError, first):
                    reconcile.reconcile(REPO, VERSION)
                self.assertEqual(collect.call_count, 5)
                self.assertEqual(publish.call_count, 4)
                self.assertNotIn(first, {call.args[1]['name'] for call in publish.call_args_list})

    def test_multiple_collection_errors_are_reported_together(self):
        first, second = list(self.runs)[:2]
        with patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', side_effect=[ValueError('first'), ValueError('second'), {}, {}, {}]), \
                patch.object(release, 'publish') as publish:
            with self.assertRaisesRegex(RuntimeError, first + '.*' + second):
                reconcile.reconcile(REPO, VERSION)
        self.assertEqual(publish.call_count, 3)

    def test_shared_publish_error_stops_remaining_platforms(self):
        with patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', return_value={}) as collect, \
                patch.object(release, 'publish', side_effect=ValueError('Existing release checksum mismatch')) as publish:
            with self.assertRaisesRegex(ValueError, 'Existing release checksum mismatch'):
                reconcile.reconcile(REPO, VERSION)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(publish.call_count, 1)

    def test_shared_manifest_error_prevents_collection(self):
        with patch.object(reconcile, 'published_slots', side_effect=ValueError('Invalid manifest')), \
                patch.object(release, 'collect') as collect:
            with self.assertRaisesRegex(ValueError, 'Invalid manifest'):
                reconcile.reconcile(REPO, VERSION)
        collect.assert_not_called()

    def test_collection_interrupt_is_not_treated_as_platform_failure(self):
        with patch.object(reconcile, 'published_slots', return_value=set()), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', side_effect=KeyboardInterrupt) as collect, \
                patch.object(release, 'publish') as publish:
            with self.assertRaises(KeyboardInterrupt):
                reconcile.reconcile(REPO, VERSION)
        self.assertEqual(collect.call_count, 1)
        publish.assert_not_called()

    def test_missing_manifest_keeps_slots_eligible_for_recovery(self):
        current = {'tag_name': 'v' + VERSION, 'draft': False,
                   'assets': [{'name': 'chromix-win-x64.zip'}]}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(release, 'gh', return_value=json.dumps([[current]])), \
                patch.object(release, 'validate_release_revision', return_value='a' * 40):
            self.assertEqual(reconcile.published_slots(REPO, 'v' + VERSION, Path(directory)), set())

    def test_discovery_bounds_precede_durable_manifest_restore(self):
        name = list(self.runs)[1]
        self.listings[name] = [run(name, number, success=False) for number in range(999, 798, -1)]
        with patch.object(reconcile, 'MAX_PAGES', 2), \
                patch.object(release, 'restore_release_manifest') as restore:
            with self.assertRaisesRegex(ValueError, 'discovery limit'):
                reconcile.reconcile(REPO, VERSION)
        restore.assert_not_called()
        self.gh.assert_not_called()

    def test_published_slots_restores_before_marking_occupied_platforms(self):
        current = {'tag_name': 'v' + VERSION, 'draft': False, 'assets': []}
        hashes = {'chromix-linux-arm64.zip': 'a' * 64, 'LICENSE.chromium': 'b' * 64}
        self.gh.side_effect = None
        self.gh.return_value = json.dumps([[current]])
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(release, 'restore_release_manifest', return_value=hashes) as restore:
            root = Path(directory)
            self.assertEqual(reconcile.published_slots(REPO, 'v' + VERSION, root), {'chromix-linux-arm64.zip'})
            restore.assert_called_once_with(REPO, 'v' + VERSION, current, root / 'published-manifest')

    def test_readiness_never_attempts_manifest_recovery(self):
        event_run = next(iter(self.runs.values()))
        with patch.object(release, 'restore_release_manifest') as restore:
            for event, name in (({}, 'workflow_dispatch'), ({'workflow_run': event_run}, 'workflow_run')):
                with self.subTest(event=name):
                    output = self.run_main(event, name, '--check-ready', version=VERSION)
                    self.assertEqual(output, f'ready=true\nversion={VERSION}\n')
        restore.assert_not_called()
        self.gh.assert_not_called()

    def test_manual_catchup_requires_main_and_version(self):
        with patch.dict(os.environ, GITHUB_REF='refs/heads/main'):
            self.assertEqual(reconcile.requested_version(REPO, {}, 'workflow_dispatch', VERSION), VERSION)
            for version in ('', '../../main', 'v' + VERSION, VERSION + '\nready=true'):
                with self.subTest(version=version), self.assertRaises(ValueError):
                    reconcile.requested_version(REPO, {}, 'workflow_dispatch', version)
        with patch.dict(os.environ, GITHUB_REF='refs/heads/other'):
            with self.assertRaises(ValueError):
                reconcile.requested_version(REPO, {}, 'workflow_dispatch', VERSION)

    def test_stale_event_still_uses_original_validated_source_version(self):
        event_run = next(iter(self.runs.values()))
        for changes in ({'run_attempt': 2, 'status': 'in_progress', 'conclusion': None},
                        {'run_attempt': 2, 'conclusion': 'failure'}, {'run_attempt': 2}):
            with self.subTest(changes=changes), patch.object(release, 'ready_run') as ready:
                self.current[event_run['id']] = {**event_run, **changes}
                self.assertEqual(reconcile.requested_version(REPO, {'workflow_run': event_run},
                                                             'workflow_run', ''), VERSION)
                ready.assert_not_called()
                self.version.assert_called_with(REPO, event_run['head_sha'], 'linux')

    def test_changed_event_identity_is_rejected(self):
        event_run = next(iter(self.runs.values()))
        for changes in ({'head_sha': 'f' * 40}, {'id': 999}, {'event': 'workflow_dispatch'},
                        {'repository': {'full_name': 'other/repo'}}, {'head_branch': 'other'},
                        {'path': '.github/workflows/other.yml'}, {'name': 'build-macos-x64'}):
            with self.subTest(changes=changes):
                self.current[event_run['id']] = {**event_run, **changes}
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    reconcile.requested_version(REPO, {'workflow_run': event_run}, 'workflow_run', '')
        self.version.assert_not_called()

    def test_invalid_original_event_is_rejected_even_if_current_run_succeeded(self):
        original = next(iter(self.runs.values()))
        for changes in ({'conclusion': 'failure'}, {'status': 'in_progress'}, {'event': 'pull_request'},
                        {'repository': {'full_name': 'other/repo'}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                reconcile.requested_version(REPO, {'workflow_run': {**original, **changes}}, 'workflow_run', '')
        self.api.assert_not_called()
        self.version.assert_not_called()

    def test_event_version_cannot_drift_from_readiness_version(self):
        event_run = next(iter(self.runs.values()))
        with self.assertRaisesRegex(ValueError, 'validated event source version'):
            reconcile.requested_version(REPO, {'workflow_run': event_run}, 'workflow_run', '153.0.0.1')

    def test_unsupported_trigger_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported release trigger'):
            reconcile.requested_version(REPO, {}, 'push', VERSION)

    def test_readiness_is_metadata_only_and_outputs_validated_version(self):
        for version in (VERSION, '153.0.0.1'):
            with self.subTest(version=version), patch.object(reconcile, 'reconcile') as publish:
                output = self.run_main({}, 'workflow_dispatch', '--check-ready', '--version', version)
                publish.assert_not_called()
                self.assertEqual(output, f'ready=true\nversion={version}\n')
        self.gh.assert_not_called()

    def test_stale_event_readiness_outputs_version_without_candidate_freshness_gate(self):
        event_run = next(iter(self.runs.values()))
        self.current[event_run['id']] = {**event_run, 'run_attempt': 2, 'status': 'in_progress', 'conclusion': None}
        with patch.object(release, 'ready_run') as ready, patch.object(reconcile, 'reconcile') as publish:
            output = self.run_main({'workflow_run': event_run}, 'workflow_run', '--check-ready')
        self.assertEqual(output, f'ready=true\nversion={VERSION}\n')
        ready.assert_not_called()
        publish.assert_not_called()
        self.gh.assert_not_called()

    def test_queued_stale_event_still_reconciles_other_missing_platforms(self):
        event_run = self.runs['build-win-x64-github']
        self.current[event_run['id']] = {**event_run, 'run_attempt': 2, 'status': 'in_progress', 'conclusion': None}
        self.listings[event_run['name']] = [self.current[event_run['id']]]
        with patch.object(reconcile, 'published_slots', return_value={'chromix-win-x64.zip'}), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', return_value={}), patch.object(release, 'publish') as publish:
            self.run_main({'workflow_run': event_run}, 'workflow_run', version=VERSION)
        self.assertEqual(publish.call_count, 5)
        self.assertNotIn(event_run['name'], {call.args[1]['name'] for call in publish.call_args_list})

    def test_late_completion_reconciles_slot_missed_by_earlier_scan(self):
        late = self.runs['build-macos-arm64']
        self.listings[late['name']] = [{**late, 'status': 'in_progress', 'conclusion': None}]
        existing = {'chromix-win-x64.zip'}

        def published(repo, item, tag, bundles, root):
            existing.update(asset + '.zip' for asset in release.WORKFLOWS[item['name']])

        with patch.object(reconcile, 'published_slots', side_effect=lambda *args: set(existing)), \
                patch.object(release, 'ready_run', side_effect=lambda repo, item: item), \
                patch.object(release, 'collect', return_value={}) as collect, \
                patch.object(release, 'publish', side_effect=published) as publish:
            reconcile.reconcile(REPO, VERSION)
            self.assertEqual(publish.call_count, 4)
            self.assertNotIn(late['name'], {call.args[1]['name'] for call in publish.call_args_list})
            self.listings[late['name']] = [late]
            collect.reset_mock()
            publish.reset_mock()
            reconcile.reconcile(REPO, VERSION)
            self.assertEqual(collect.call_count, 1)
            self.assertEqual(publish.call_count, 1)
            self.assertEqual(publish.call_args.args[1], late)
        self.assertEqual(existing, release.ASSETS)

    def test_newer_run_at_original_sha_does_not_suppress_coalesced_wakeup(self):
        event_run = next(iter(self.runs.values()))
        self.listings[event_run['name']].insert(0, run(event_run['name'], 999,
                                                       head_sha=event_run['head_sha'], success=False))
        with patch.object(reconcile, 'reconcile') as publish:
            self.run_main({'workflow_run': event_run}, 'workflow_run', version=VERSION)
        publish.assert_called_once_with(REPO, VERSION)

    def test_workflow_uses_validated_version_queue_and_pinned_controller(self):
        source = (Path(__file__).resolve().parents[2] / '.github/workflows/release-browser.yml').read_text()
        readiness, publishing = source.split('\n  release:\n', 1)
        self.assertIn('version: ${{ steps.check.outputs.version }}', readiness)
        self.assertIn('ref: main', readiness)
        self.assertIn('controller_sha: ${{ steps.controller.outputs.sha }}', readiness)
        self.assertIn('group: release-browser-publish-${{ needs.readiness.outputs.version }}', publishing)
        self.assertIn('cancel-in-progress: false', publishing)
        self.assertIn('RELEASE_VERSION: ${{ needs.readiness.outputs.version }}', publishing)
        self.assertIn('ref: ${{ needs.readiness.outputs.controller_sha }}', publishing)
        self.assertNotIn('ref: ${{ github.event.workflow_run.head_sha }}', source)
        self.assertNotIn('RELEASE_VERSION: ${{ inputs.version }}', publishing)


if __name__ == '__main__':
    unittest.main()

import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from tools import validate_posix_snapshot as posix
from tools import validate_windows_snapshot as snapshot


REPO = 'owner/Chromix'
RUN_ID = 35054494898
SHA = '97f2881b0e5f43b7e9563569d92dfe702ed1df0b'
ARTIFACT_IDS = [10462681393, 10462257055]
RECOVERY_BRANCH = 'repair/windows-font-0152'


class Client:
    def __init__(self, run_id=RUN_ID, stage=3, attempt=1, sha=SHA):
        self.run = {'id': run_id, 'name': 'build-win-x64-github',
                    'path': '.github/workflows/build-win-x64-github.yml',
                    'head_branch': 'main', 'event': 'push',
                    'repository': {'full_name': REPO}, 'head_repository': {'full_name': REPO},
                    'status': 'completed', 'conclusion': 'failure', 'head_sha': sha, 'run_attempt': attempt}
        description = 'fetch + sync + first compile' if stage == 1 else 'resume compile'
        self.jobs = [{'id': 456, 'run_id': run_id, 'run_attempt': attempt, 'head_sha': sha,
                      'name': f'stage {stage} ({description})',
                      'status': 'completed', 'conclusion': 'failure', 'steps': [
                          {'name': 'Ensure build tree snapshot', 'conclusion': 'success'},
                          *[{'name': f'Upload tree part {n}', 'conclusion': 'success'} for n in range(1, 5)]]}]
        self.artifacts = [
            {'id': identifier, 'name': f'tree-s{stage}-attempt-{attempt}-part{n}',
             'size_in_bytes': 1024, 'expired': False, 'digest': 'sha256:' + 'b' * 64,
             'workflow_run': {'id': run_id, 'head_sha': sha}}
            for n, identifier in enumerate(ARTIFACT_IDS, 1)]
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path != f'/actions/runs/{self.run["id"]}':
            raise AssertionError(f'unexpected metadata endpoint: {path}')
        return self.run

    def items(self, path, key):
        self.calls.append(path)
        if key not in ('jobs', 'artifacts'):
            raise AssertionError(f'unexpected metadata collection: {key}')
        return self.jobs if key == 'jobs' else self.artifacts


class SnapshotValidationTest(unittest.TestCase):
    def validate(self, client=None, **changes):
        options = dict(repository=REPO, run_id=RUN_ID, stage=3, attempt=1,
                       expected_sha=SHA, expected_artifact_ids=ARTIFACT_IDS)
        options.update(changes)
        return snapshot.validate(client if client is not None else Client(), **options)

    def test_failed_cold_build_with_two_parts_and_four_successful_uploads(self):
        client = Client()
        client.artifacts.reverse()
        report = self.validate(client)
        self.assertEqual(report, {
            'repository': REPO, 'platform': 'windows', 'arch': 'x64',
            'workflow': 'build-win-x64-github', 'run_id': RUN_ID, 'stage': 3, 'attempt': 1,
            'head_sha': SHA, 'job_id': 456, 'pattern': 'tree-s3-attempt-1-part*',
            'artifacts': [{key: item[key] for key in ('id', 'name', 'size_in_bytes', 'expired', 'digest')}
                          for item in reversed(client.artifacts)],
        })
        self.assertEqual(client.calls, [f'/actions/runs/{RUN_ID}',
                                      f'/actions/runs/{RUN_ID}/attempts/1/jobs',
                                      f'/actions/runs/{RUN_ID}/artifacts'])

    def test_main_push_and_manual_completed_success_or_failure(self):
        for event in ('push', 'workflow_dispatch'):
            for conclusion in ('success', 'failure'):
                with self.subTest(event=event, conclusion=conclusion):
                    client = Client()
                    client.run.update(event=event, conclusion=conclusion)
                    client.jobs[0]['conclusion'] = conclusion
                    self.validate(client, recovery_branch=RECOVERY_BRANCH)

    def test_stage_run_sha_and_attempt_are_parameterized(self):
        for stage in (1, 2, 3, 12):
            with self.subTest(stage=stage):
                client = Client(run_id=1, stage=stage, attempt=3, sha='a' * 40)
                report = self.validate(client, run_id=1, stage=stage, attempt=3, expected_sha='a' * 40)
                self.assertEqual(report['pattern'], f'tree-s{stage}-attempt-3-part*')
                self.assertEqual(report['head_sha'], 'a' * 40)
                self.assertEqual(report['attempt'], 3)
                self.assertIn('/actions/runs/1/attempts/3/jobs', client.calls)

    def test_exact_stage9_donor_with_successful_checkpoint_after_acceptance_failure(self):
        sha = '30dbab28692793fa311c82ae639186003f3a67d9'
        branch = 'fix/issue3-font-resume-20260917'
        identifiers = [10536907942, 10536997738]
        client = Client(run_id=35315624638, stage=9, attempt=1, sha=sha)
        client.run.update(head_branch=branch, event='workflow_dispatch')
        client.jobs[0]['steps'].insert(0, {'name': 'Compile and acceptance', 'conclusion': 'failure'})
        for artifact, identifier in zip(client.artifacts, identifiers):
            artifact['id'] = identifier
        options = dict(run_id=35315624638, stage=9, attempt=1, expected_sha=sha,
                       expected_artifact_ids=identifiers, recovery_branch=branch)
        report = self.validate(client, **options)
        self.assertEqual(report['head_sha'], sha)
        self.assertEqual(report['pattern'], 'tree-s9-attempt-1-part*')
        for field, value in (('expected_sha', SHA), ('attempt', 2), ('stage', 8),
                             ('expected_artifact_ids', ARTIFACT_IDS), ('recovery_branch', RECOVERY_BRANCH)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(client, **dict(options, **{field: value}))

    def test_one_through_four_contiguous_parts_are_valid(self):
        for count in range(1, 5):
            with self.subTest(count=count):
                client = Client()
                client.artifacts = [dict(copy.deepcopy(client.artifacts[0]), id=100 + n,
                                         name=f'tree-s3-attempt-1-part{n}') for n in range(1, count + 1)]
                report = self.validate(client, expected_artifact_ids=list(range(101, 101 + count)))
                self.assertEqual(len(report['artifacts']), count)

    def test_exact_old_producer_attempt_survives_completed_retry(self):
        client = Client()
        client.run['run_attempt'] = 2
        for name in ('tree-s3-attempt-2-part1', 'tree-s2-attempt-1-part1',
                     'chromix-win-x64-tree-s3-attempt-1-part1', 'diagnostics'):
            client.artifacts.append(dict(copy.deepcopy(client.artifacts[0]), id=900 + len(client.artifacts), name=name))
        report = self.validate(client)
        self.assertEqual(report['attempt'], 1)
        self.assertEqual([item['id'] for item in report['artifacts']], ARTIFACT_IDS)
        self.assertIn(f'/actions/runs/{RUN_ID}/attempts/1/jobs', client.calls)
        with self.assertRaisesRegex(ValueError, 'attempt'):
            self.validate(client, attempt=2)
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.validate(client, attempt=3)

    def test_recovery_branch_is_explicit_exact_and_manual_only(self):
        client = Client()
        client.run.update(head_branch=RECOVERY_BRANCH, event='workflow_dispatch')
        self.assertEqual(self.validate(client, recovery_branch=RECOVERY_BRANCH)['head_sha'], SHA)
        for branch in (None, 'repair/other', 'repair/*', RECOVERY_BRANCH.upper(), 'refs/heads/' + RECOVERY_BRANCH):
            with self.subTest(branch=branch), self.assertRaisesRegex(ValueError, 'identity'):
                self.validate(client, recovery_branch=branch)
        for event in ('push', 'pull_request', 'workflow_run', 'workflow_call', 'schedule', 'manual'):
            client.run['event'] = event
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'identity'):
                self.validate(client, recovery_branch=RECOVERY_BRANCH)

    def test_invalid_selection_and_strict_numeric_types_before_api(self):
        cases = {'run_id': [None, True, False, 0, -1, '1', 1.0, [], {}],
                 'stage': [None, True, False, 0, 13, -1, '3', 3.0, [], {}],
                 'attempt': [None, True, False, 0, -1, '1', 1.0, [], {}],
                 'repository': [None, True, [], {}, '', 'owner', '/owner/repo', 'owner/repo/extra',
                                '../repo', 'owner/..', './repo', 'owner/.', 'owner/repo\n', 'owner/repo?x=1'],
                 'expected_sha': [None, True, [], {}, '', 'a' * 39, 'a' * 41, 'g' * 40, SHA.upper(),
                                  SHA + '\n', ' ' + SHA, '97f2881'],
                 'expected_artifact_ids': [None, True, [], (), {}, [True], [False], [1.0], ['1'], [0],
                                           [-1], [None], [[]], [{}], [1, 1], [1, 2, 3, 4, 5]],
                 'recovery_branch': [True, 1, [], {}, '', 'repair/branch\n', 'repair/branch\x00',
                                     ' repair/branch', 'repair/ branch', 'repair/branch\x7f']}
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    client = Client()
                    with self.assertRaises(ValueError):
                        self.validate(client, **{field: value})
                    self.assertEqual(client.calls, [])

    def test_expected_sha_cannot_be_replaced_by_consistent_remote_tampering(self):
        with self.assertRaisesRegex(ValueError, 'SHA'):
            self.validate(Client(sha='a' * 40))

    def test_run_identity_types_and_missing_fields(self):
        cases = {
            'id': [None, True, str(RUN_ID), float(RUN_ID), RUN_ID + 1, [], {}],
            'name': [None, [], {}, 'build-win-arm64-github', 'build-macos-x64', 'build-win-x64'],
            'path': [None, [], '.github/workflows/other.yml',
                     '.github/workflows/build-win-x64-github.yml@refs/heads/main'],
            'head_branch': [None, False, [], {}, '', 'Main', 'refs/heads/main', 'feature'],
            'event': [None, [], {}, 'pull_request', 'workflow_call', 'schedule', 'manual'],
            'repository': [None, [], '', {}, {'full_name': 'foreign/Chromix'}, {'full_name': []}],
            'head_repository': [None, [], '', {}, {'full_name': 'foreign/Chromix'}, {'full_name': []}],
            'status': [None, [], 'queued', 'in_progress', 'waiting'],
            'head_sha': [None, True, [], {}, 'a' * 40, SHA.upper(), SHA + '\n'],
            'run_attempt': [None, True, False, 0, -1, 1.0, '1', [], {}],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    client = Client()
                    client.run[field] = value
                    with patch.object(client, 'get', return_value=client.run), self.assertRaises(ValueError):
                        self.validate(client)
            with self.subTest(missing=field):
                client = Client()
                del client.run[field]
                with patch.object(client, 'get', return_value=client.run), self.assertRaises(ValueError):
                    self.validate(client)
        for run in (None, [], '', 1, True):
            with self.subTest(run=run), patch.object(Client, 'get', return_value=run), self.assertRaises(ValueError):
                self.validate()

    def test_job_identity_attempt_sha_and_types(self):
        cases = {
            'id': [None, True, False, 0, -1, '456', 456.0, [], {}],
            'run_id': [None, True, str(RUN_ID), float(RUN_ID), RUN_ID + 1, [], {}],
            'run_attempt': [None, True, False, 0, 2, 1.0, '1', [], {}],
            'head_sha': [None, [], {}, 'a' * 40, SHA.upper()],
            'name': [None, [], {}, 'stage 2 (resume compile)', 'stage 3 (other)',
                     'build / stage 3 (resume compile)', 'windows-x64 stage 3 (resume compile)',
                     'stage 3 (resume compile)\n'],
            'status': [None, [], {}, 'in_progress', 'queued'],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    client = Client()
                    client.jobs[0][field] = value
                    with self.assertRaises(ValueError):
                        self.validate(client)
            with self.subTest(missing=field):
                client = Client()
                del client.jobs[0][field]
                with self.assertRaises(ValueError):
                    self.validate(client)

    def test_missing_duplicate_and_malformed_jobs(self):
        for jobs in (None, {}, '', True, [], [None], ['job'], [{}], [Client().jobs[0]] * 2):
            with self.subTest(jobs=jobs):
                client = Client()
                client.jobs = jobs
                with self.assertRaises(ValueError):
                    self.validate(client)
        client = Client()
        client.jobs.append(dict(client.jobs[0], name='stage 4 (resume compile)'))
        self.validate(client)

    def test_all_snapshot_steps_must_succeed_even_unused_slots(self):
        for index in range(5):
            for conclusion in ('failure', 'skipped', 'cancelled', 'neutral', None, True, [], {}):
                with self.subTest(index=index, conclusion=conclusion):
                    client = Client()
                    client.jobs[0]['steps'][index]['conclusion'] = conclusion
                    with self.assertRaisesRegex(ValueError, 'checkpoint step'):
                        self.validate(client)
            for action in ('missing', 'duplicate', 'renamed', 'missing_conclusion'):
                with self.subTest(index=index, action=action):
                    client = Client()
                    steps = client.jobs[0]['steps']
                    if action == 'missing':
                        del steps[index]
                    elif action == 'duplicate':
                        steps.append(copy.deepcopy(steps[index]))
                    elif action == 'renamed':
                        steps[index]['name'] += ' '
                    else:
                        del steps[index]['conclusion']
                    with self.assertRaises(ValueError):
                        self.validate(client)

    def test_malformed_or_missing_steps(self):
        for steps in (None, {}, '', True, [], [None], ['step'], [{}], [{'name': []}], [{'name': 3}]):
            with self.subTest(steps=steps):
                client = Client()
                client.jobs[0]['steps'] = steps
                with self.assertRaises(ValueError):
                    self.validate(client)
        client = Client()
        del client.jobs[0]['steps']
        with self.assertRaises(ValueError):
            self.validate(client)

    def test_complete_artifact_id_set_not_subset(self):
        cases = [[], Client().artifacts[:1], Client().artifacts[1:]]
        extra = dict(copy.deepcopy(Client().artifacts[0]), id=900, name='tree-s3-attempt-1-part3')
        cases.append(Client().artifacts + [extra])
        cases.append(Client().artifacts + [Client().artifacts[0]])
        cases.append([dict(item, id=item['id'] + 10) for item in Client().artifacts])
        for artifacts in cases:
            with self.subTest(artifacts=artifacts):
                client = Client()
                client.artifacts = artifacts
                with self.assertRaises(ValueError):
                    self.validate(client)
        for ids in (ARTIFACT_IDS[:1], ARTIFACT_IDS + [900], [900, 901]):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.validate(expected_artifact_ids=ids)
        self.validate(expected_artifact_ids=list(reversed(ARTIFACT_IDS)))

    def test_duplicate_ids_cannot_disguise_two_parts(self):
        client = Client()
        client.artifacts[1]['id'] = ARTIFACT_IDS[0]
        with self.assertRaisesRegex(ValueError, 'complete recorded ID set'):
            self.validate(client, expected_artifact_ids=ARTIFACT_IDS[:1])

    def test_part_names_are_exact_contiguous_unique_and_attempt_scoped(self):
        for name in ('tree-s3-attempt-1-part1', 'tree-s3-attempt-1-part3', 'tree-s3-attempt-1-part5',
                     'tree-s3-attempt-1-part0', 'tree-s3-attempt-1-part02', 'tree-s3-attempt-1-part2-extra',
                     'tree-s3-attempt-1-part2\n', 'tree-s3-attempt-1-part', 'tree-s3-attempt-2-part2',
                     'tree-s3-attempt-10-part2', 'tree-s2-attempt-1-part2', 'tree-s03-attempt-1-part2',
                     'tree-s3-attempt-01-part2', 'chromix-win-x64-tree-s3-attempt-1-part2'):
            with self.subTest(name=name):
                client = Client()
                client.artifacts[1]['name'] = name
                with self.assertRaises(ValueError):
                    self.validate(client)
        for suffix in ('', '0', '5', '01', '3-extra'):
            with self.subTest(extra_suffix=suffix):
                client = Client()
                client.artifacts.append(dict(client.artifacts[0], id=900,
                                             name='tree-s3-attempt-1-part' + suffix))
                with self.assertRaises(ValueError):
                    self.validate(client)
                with self.assertRaises(ValueError):
                    self.validate(client, expected_artifact_ids=ARTIFACT_IDS + [900])

    def test_artifact_shape_types_expiry_size_digest_and_origin(self):
        cases = {
            'id': [None, True, False, 0, -1, float(ARTIFACT_IDS[0]), str(ARTIFACT_IDS[0]), [], {}],
            'name': [None, True, [], {}],
            'expired': [None, True, 0, 1, 'false', [], {}],
            'size_in_bytes': [None, True, False, 0, -1, 1.0, '1024', [], {}],
            'digest': [None, True, [], {}, '', 'sha256:bad', 'sha512:' + 'b' * 64,
                       'SHA256:' + 'b' * 64, 'sha256:' + 'B' * 64, 'sha256:' + 'b' * 63,
                       'sha256:' + 'b' * 65, 'sha256:' + 'b' * 64 + '\n'],
            'workflow_run': [None, True, [], {}, 'origin', {'id': RUN_ID}, {'head_sha': SHA},
                             {'id': True, 'head_sha': SHA}, {'id': str(RUN_ID), 'head_sha': SHA},
                             {'id': float(RUN_ID), 'head_sha': SHA}, {'id': RUN_ID + 1, 'head_sha': SHA},
                             {'id': RUN_ID, 'head_sha': 'a' * 40}, {'id': RUN_ID, 'head_sha': []}],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    client = Client()
                    client.artifacts[0][field] = value
                    with self.assertRaises(ValueError):
                        self.validate(client)
            with self.subTest(missing=field):
                client = Client()
                del client.artifacts[0][field]
                with self.assertRaises(ValueError):
                    self.validate(client)
        for artifacts in (None, {}, '', True, [None], ['artifact'], [{}]):
            with self.subTest(artifacts=artifacts):
                client = Client()
                client.artifacts = artifacts
                with self.assertRaises(ValueError):
                    self.validate(client)

    def test_api_numeric_booleans_and_floats_cannot_equal_one(self):
        for value in (True, 1.0):
            for target in ('run', 'job', 'artifact', 'origin'):
                with self.subTest(value=value, target=target):
                    client = Client(run_id=1)
                    client.artifacts = [dict(client.artifacts[0], id=1)]
                    if target == 'run':
                        client.run['id'] = value
                    elif target == 'job':
                        client.jobs[0]['run_id'] = value
                    elif target == 'artifact':
                        client.artifacts[0]['id'] = value
                    else:
                        client.artifacts[0]['workflow_run']['id'] = value
                    with patch.object(client, 'get', return_value=client.run), self.assertRaises(ValueError):
                        self.validate(client, run_id=1, expected_artifact_ids=[1])


class MetadataClientTest(unittest.TestCase):
    def test_reuses_posix_client_and_does_not_forward_token_on_redirect(self):
        self.assertTrue(issubclass(snapshot.Client, posix.Client))
        for code in (301, 302, 303, 307, 308):
            for location in ('https://foreign.invalid/metadata', 'https://['):
                with self.subTest(code=code, location=location):
                    client = snapshot.Client(REPO, 'fixture-token')
                    redirect = next(handler for handler in client.opener.handlers if isinstance(handler, posix.NoRedirect))
                    request = urllib.request.Request(client.base + '/actions/runs/1',
                                                     headers={'Authorization': 'Bearer fixture-token'})
                    self.assertIsNone(redirect.redirect_request(request, None, code, 'Found', {}, location))
                    with self.assertRaises(urllib.error.HTTPError):
                        getattr(redirect, f'http_error_{code}')(request, None, code, 'Found', {'Location': location})
                    error = urllib.error.HTTPError(request.full_url, code, 'Found', {'Location': location}, None)
                    with patch.object(client.opener, 'open', side_effect=error) as opened:
                        with self.assertRaises(urllib.error.HTTPError):
                            client.get('/actions/runs/1')
                    self.assertEqual(opened.call_count, 1)
                    self.assertEqual(opened.call_args.args[0].get_header('Authorization'), 'Bearer fixture-token')

    def test_paginated_validation_uses_only_same_origin_metadata_gets(self):
        fixture = Client()
        jobs = [{'id': n, 'name': 'unrelated job'} for n in range(100)]
        artifacts = [{'id': n + 1, 'name': 'diagnostic'} for n in range(100)]
        responses = [fixture.run, {'jobs': jobs, 'total_count': 101},
                     {'jobs': fixture.jobs, 'total_count': 101},
                     {'artifacts': artifacts, 'total_count': 102},
                     {'artifacts': fixture.artifacts, 'total_count': 102}]
        client = snapshot.Client(REPO, 'fixture-token')
        with patch.object(client.opener, 'open', side_effect=[io.BytesIO(json.dumps(item).encode())
                                                            for item in responses]) as opened:
            report = snapshot.validate(client, REPO, RUN_ID, 3, 1, SHA, ARTIFACT_IDS)
        self.assertEqual([item['id'] for item in report['artifacts']], ARTIFACT_IDS)
        paths = [f'/actions/runs/{RUN_ID}',
                 f'/actions/runs/{RUN_ID}/attempts/1/jobs?per_page=100&page=1',
                 f'/actions/runs/{RUN_ID}/attempts/1/jobs?per_page=100&page=2',
                 f'/actions/runs/{RUN_ID}/artifacts?per_page=100&page=1',
                 f'/actions/runs/{RUN_ID}/artifacts?per_page=100&page=2']
        self.assertEqual(opened.call_count, len(paths))
        for call, path in zip(opened.call_args_list, paths):
            request = call.args[0]
            self.assertEqual(request.full_url, 'https://api.github.com/repos/' + REPO + path)
            self.assertEqual(request.get_method(), 'GET')
            self.assertIsNone(request.data)
            self.assertEqual(call.kwargs, {'timeout': 30})
            self.assertEqual(request.get_header('Authorization'), 'Bearer fixture-token')

    def test_paginated_shapes_are_strict_and_incomplete_sets_fail_closed(self):
        for key in ('jobs', 'artifacts'):
            cases = [{}, {key: []}, {'total_count': 0}, {key: [], 'total_count': 1},
                     {key: [{}], 'total_count': 0}]
            cases += [{key: [], 'total_count': value} for value in (None, True, False, 0.0, -1, '0', [], {})]
            cases += [{key: value, 'total_count': 0} for value in (None, True, '', {})]
            for data in cases:
                with self.subTest(key=key, data=data):
                    client = snapshot.Client(REPO, 'fixture-token')
                    with patch.object(client.opener, 'open', return_value=io.BytesIO(json.dumps(data).encode())):
                        with self.assertRaises(ValueError):
                            client.items(f'/actions/runs/{RUN_ID}/' + key, key)

    def test_pagination_is_bounded(self):
        client = snapshot.Client(REPO, 'fixture-token')
        data = json.dumps({'jobs': [{}] * 100, 'total_count': 2001}).encode()
        with patch.object(client.opener, 'open', side_effect=lambda *args, **kwargs: io.BytesIO(data)) as opened:
            with self.assertRaisesRegex(ValueError, 'incomplete GitHub pagination'):
                client.items('/actions/runs/1/attempts/1/jobs', 'jobs')
        self.assertEqual(opened.call_count, 20)

    def test_metadata_size_json_and_root_shape(self):
        for raw in (b'x' * (posix.LIMIT + 1), b'not json', b'[]', b'null', b'1', b'true'):
            with self.subTest(size=len(raw)):
                client = snapshot.Client(REPO, 'fixture-token')
                with patch.object(client.opener, 'open', return_value=io.BytesIO(raw)):
                    with self.assertRaises(ValueError):
                        client.get('/actions/runs/1')

    def test_token_required(self):
        with self.assertRaisesRegex(ValueError, 'token is required'):
            snapshot.Client(REPO, '')


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.report = self.root / 'nested' / 'report.json'
        self.output = self.root / 'github-output'
        self.argv = ['validate_windows_snapshot.py', '--repository', REPO,
                     '--run-id', str(RUN_ID), '--stage', '3', '--attempt', '1', '--expected-sha', SHA,
                     '--artifact-ids', ','.join(map(str, ARTIFACT_IDS)), '--report', str(self.report)]

    def main(self, client, *, output=False, argv=None):
        env = {'GH_TOKEN': 'fixture-token'}
        if output:
            env['GITHUB_OUTPUT'] = str(self.output)
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', argv or self.argv), \
                patch.object(snapshot, 'Client', return_value=client) as constructor, \
                patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = snapshot.main()
        constructor.assert_called_once_with(REPO, 'fixture-token')
        self.assertEqual(result, 0)
        return json.loads(stdout.getvalue())

    def test_report_and_optional_output_preserve_exact_safe_identity(self):
        self.output.write_text('existing=value\n', encoding='utf-8')
        report = self.main(Client(), output=True)
        self.assertEqual(report, json.loads(self.report.read_text(encoding='utf-8')))
        self.assertEqual(self.output.read_text(encoding='utf-8'),
                         f'existing=value\nhead_sha={SHA}\npattern=tree-s3-attempt-1-part*\n')

    def test_output_is_optional_and_recovery_branch_is_explicit(self):
        client = Client()
        client.run.update(head_branch=RECOVERY_BRANCH, event='workflow_dispatch')
        report = self.main(client, argv=self.argv + ['--recovery-branch', RECOVERY_BRANCH])
        self.assertEqual(report['head_sha'], SHA)
        self.assertFalse(self.output.exists())

    def test_validation_failure_writes_neither_report_nor_output(self):
        for mutation in ('sha', 'extra_part', 'unused_upload'):
            with self.subTest(mutation=mutation):
                client = Client()
                if mutation == 'sha':
                    client.run['head_sha'] = 'a' * 40
                elif mutation == 'extra_part':
                    client.artifacts.append(dict(client.artifacts[0], id=900, name='tree-s3-attempt-1-part3'))
                else:
                    client.jobs[0]['steps'][4]['conclusion'] = 'skipped'
                with self.assertRaises(ValueError):
                    self.main(client, output=True)
                self.assertFalse(self.report.exists())
                self.assertFalse(self.output.exists())

    def test_invalid_cli_numbers_and_sha_do_not_call_api(self):
        for flag, values in {
            '--run-id': ('', '0', '-1', '01', '1.0', 'true', '1\nhead_sha=bad'),
            '--stage': ('0', '13', '03'), '--attempt': ('0', '01'),
            '--expected-sha': ('', SHA[:7], SHA + '\n', SHA.upper()),
            '--artifact-ids': ('', '1,', ',1', '1,,2', '1,1', 'true', '01', '1.0', '1,2,3,4,5'),
        }.items():
            for value in values:
                with self.subTest(flag=flag, value=value):
                    argv = self.argv.copy()
                    argv[argv.index(flag) + 1] = value
                    client = Client()
                    with self.assertRaises(ValueError):
                        self.main(client, output=True, argv=argv)
                    self.assertEqual(client.calls, [])
                    self.assertFalse(self.report.exists())
                    self.assertFalse(self.output.exists())

    def test_identity_and_report_flags_are_required(self):
        for flag in ('--repository', '--run-id', '--stage', '--attempt', '--expected-sha', '--artifact-ids', '--report'):
            with self.subTest(flag=flag):
                argv = self.argv.copy()
                index = argv.index(flag)
                del argv[index:index + 2]
                with patch.object(sys, 'argv', argv), patch('sys.stderr', new_callable=io.StringIO), \
                        patch.object(snapshot, 'Client') as client, self.assertRaises(SystemExit) as raised:
                    snapshot.main()
                self.assertEqual(raised.exception.code, 2)
                client.assert_not_called()

    def test_script_and_module_entry_points(self):
        source = Path(snapshot.__file__).resolve().parents[1]
        commands = ([sys.executable, str(Path(snapshot.__file__).resolve()), '--help'],
                    [sys.executable, '-m', 'tools.validate_windows_snapshot', '--help'])
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=source, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                for flag in ('--repository', '--run-id', '--stage', '--attempt', '--expected-sha',
                             '--artifact-ids', '--recovery-branch', '--report'):
                    self.assertIn(flag, result.stdout)


if __name__ == '__main__':
    unittest.main()

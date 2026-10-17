"""Controlled independent-review predicates; no signing/seed/provider effects."""

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch


SOURCE = Path(__file__).with_name('_hub-direct-issuer-clock-reviewer.py')
spec = importlib.util.spec_from_file_location('clock_reviewer', SOURCE)
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)
ADAPTER_SOURCE = SOURCE.with_name('_hub-direct-issuer-clock-review.py')
adapter_spec = importlib.util.spec_from_file_location('clock_review_adapter', ADAPTER_SOURCE)
adapter = importlib.util.module_from_spec(adapter_spec)
adapter_spec.loader.exec_module(adapter)


# Existing inlined decoder; this binding belongs only to the standalone test.
def _closed_review_json(body):
    """Reject duplicate fields before interpreting an independent selection."""
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("independent review contains duplicate fields")
            result[key] = value
        return result

    return json.loads(body, object_pairs_hook=object_pairs)


adapter._closed_review_json = _closed_review_json


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


class IndependentClockReviewTests(unittest.TestCase):
    def facts(self):
        authority = {'authority_id': '00000000-0000-4000-8000-000000000001',
            'guard_namespace_id': 'isolated', 'physical_resource_evidence_digest': '1' * 64,
            'qualification_digest': '2' * 64, 'qualified_managed_prefix': 'isolated/production'}
        installation = {'format_version': 1, 'authority': authority, 'issuer_resource_id': 'fresh',
            'runtime_identity': 'current', 'executor_identity': 'executor'}
        timing = {'profile_id': 'current', 'review_digest': '3' * 64,
            'maximum_lifetime': '120', 'maximum_clock_uncertainty': '3'}
        journal = {'authority': authority, 'executor_identity': 'executor', 'generation': '1',
            'admission_digest': '4' * 64, 'publication_digest': '5' * 64, 'state': 'admitted',
            'policy': {'timing_profile': timing}, 'last_sequence': '2', 'largest_issued_expiry': '120', 'clock_floor': '100'}
        head = {'installation': installation, 'journal': journal}
        policy = {'version': 1, 'reviewer_key_id': 'independent', 'reviewer_public_key': '6' * 64,
            'resource_qualification_digest': '7' * 64, 'clock_qualification_digest': '8' * 64,
            'maximum_review_seconds': '30', 'clock_uncertainty': '1', 'clock_commit_latency': '1'}
        policy_bytes = encode(policy)
        files = {'device': '1', 'inode': '2', 'parent_device': '3', 'parent_inode': '4'}
        snapshot = {'signedHead': head, 'clockRecoveryPolicy': policy, 'issuerSigningKeyId': 'issuer',
            'journalFile': files, 'clockFloor': '100', 'clockCeiling': '103',
            'clockSessionSha256': hashlib.sha256(('9' * 64).encode()).hexdigest()}
        auth = {'version': 1, 'snapshot': snapshot, 'policySha256': hashlib.sha256(policy_bytes).hexdigest()}
        plan = {'version': 1, 'file': copy.deepcopy(files), 'expected_head': copy.deepcopy(head),
            'expected_session': '9' * 64, 'expected_floor': '100', 'expected_ceiling': '103',
            'policy_digest': auth['policySha256'], 'successor_session': 'a' * 64, 'nonce': 'b' * 64,
            'issued_at': '123', 'expires_at': '153'}
        return plan, policy_bytes, auth

    def test_exact_authorized_original_and_monotone_clock_are_allowed(self):
        plan, policy, authorization = self.facts()
        reviewer.review_predicates(encode(plan), policy, authorization)
        plan['expected_head']['journal']['clock_floor'] = '110'
        plan['expected_floor'], plan['expected_ceiling'] = '110', '113'
        reviewer.review_predicates(encode(plan), policy, authorization)

    def test_changed_epoch_issue_history_resource_session_and_policy_refuse(self):
        for section, field, value in (('file', 'inode', '99'), ('expected_head', 'installation', {}),
                ('plan', 'expected_session', '0' * 64), ('plan', 'policy_digest', '0' * 64),
                ('journal', 'last_sequence', '3'), ('journal', 'largest_issued_expiry', '121'),
                ('journal', 'generation', '2')):
            plan, policy, authorization = self.facts()
            selected = plan if section == 'plan' else plan['expected_head']['journal'] if section == 'journal' else plan[section]
            selected[field] = value
            with self.assertRaises(ValueError):
                reviewer.review_predicates(encode(plan), policy, authorization)

    def test_early_expired_long_lived_bool_and_noncanonical_plan_refuse(self):
        for field, value in (('version', True), ('issued_at', '122'), ('expires_at', '154'),
                ('expires_at', '123'), ('expected_floor', '099'), ('expected_ceiling', str(2**63)),
                ('successor_session', '9' * 64)):
            plan, policy, authorization = self.facts()
            plan[field] = value
            with self.assertRaises(ValueError):
                reviewer.review_predicates(encode(plan), policy, authorization)
        plan, policy, authorization = self.facts()
        for body in (json.dumps(plan).encode(), encode(plan) + b'\n', encode(dict(reversed(list(plan.items()))))):
            with self.assertRaises(ValueError):
                reviewer.review_predicates(body, policy, authorization)

    def test_retained_refusal_requires_exact_owner_history_and_public_material(self):
        plan, policy, authorization = self.facts()
        basis = authorization['snapshot']
        basis.update({'process': {'pid': 7, 'startTicks': '11'}, 'authorityExecutableSha256': 'c' * 64,
            'historySha256': 'd' * 64, 'historyRows': 1, 'configurationSha256': 'e' * 64,
            'publicKeySha256': 'f' * 64, 'secretCustody': {'signing-seed.key':
                {'device': '10', 'inode': '11', 'bytes': 64, 'mtimeNs': '12',
                    'owner': 1000, 'mode': 0o600, 'links': 1}}})
        refusal = {'oldPid': 7, 'oldStartTicks': '11', 'executableSha256': 'c' * 64, 'exitCode': 1,
            'retainedHistory': {'journalFormat': 3, 'historySha256': 'd' * 64, 'historyRows': 1,
                'clockSessionSha256': basis['clockSessionSha256'], 'clockFloor': '100', 'clockCeiling': '103'},
            'retainedResource': {'journalDevice': 1, 'journalInode': 2, 'journalParentDevice': 3, 'journalParentInode': 4,
                'files': {'configuration.json': 'e' * 64, 'issuer-public-key.hex': 'f' * 64,
                    'signing-seed.key': {'device': 10, 'inode': 11, 'bytes': 64, 'mtimeNs': '12',
                        'owner': 1000, 'mode': 0o600, 'links': 1}}}}
        reviewer.retained_refusal_predicates(refusal, basis)
        for field, value in (('historySha256', '0' * 64), ('historyRows', 2), ('clockFloor', '99')):
            changed = copy.deepcopy(refusal)
            changed['retainedHistory'][field] = value
            with self.assertRaises(ValueError):
                reviewer.retained_refusal_predicates(changed, basis)
        changed = copy.deepcopy(refusal)
        changed['retainedResource']['files']['signing-seed.key']['inode'] = 99
        with self.assertRaises(ValueError):
            reviewer.retained_refusal_predicates(changed, basis)
        for value in (None, True, 0):
            changed = copy.deepcopy(refusal)
            changed['exitCode'] = value
            with self.assertRaises(ValueError):
                reviewer.retained_refusal_predicates(changed, basis)

    def test_distinct_reviewer_and_canonical_finite_policy_are_required(self):
        for field, value in (('version', True), ('maximum_review_seconds', '31'),
                ('maximum_review_seconds', '030'), ('reviewer_key_id', 'issuer')):
            plan, policy_bytes, authorization = self.facts()
            policy = json.loads(policy_bytes)
            policy[field] = value
            policy_bytes = encode(policy)
            authorization['snapshot']['clockRecoveryPolicy'] = policy
            authorization['policySha256'] = hashlib.sha256(policy_bytes).hexdigest()
            plan['policy_digest'] = authorization['policySha256']
            with self.assertRaises(ValueError):
                reviewer.review_predicates(encode(plan), policy_bytes, authorization)

    def test_pipe_deadline_and_duplicate_frames_refuse(self):
        import os
        import time
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"version":1}\n{"version":1}\n')
            with os.fdopen(read_fd, 'rb') as incoming:
                with self.assertRaises(ValueError):
                    reviewer.receive_frame(incoming, time.monotonic() + 1, 1024)
            read_fd = None
        finally:
            if read_fd is not None:
                os.close(read_fd)
            os.close(write_fd)
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, 'rb') as incoming:
                with self.assertRaises(ValueError):
                    reviewer.receive_frame(incoming, time.monotonic() - 1, 1024)
            read_fd = None
        finally:
            if read_fd is not None:
                os.close(read_fd)
            os.close(write_fd)

    def test_seed_custody_function_has_no_content_reader(self):
        tree = ast.parse(SOURCE.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'seed_metadata')
        body = ast.get_source_segment(SOURCE.read_text(), function)
        self.assertIn('.lstat()', body)
        for name in ('os.open(', '.open(', 'read_bytes(', 'read_text(', 'sha256(', 'file_digest('):
            self.assertNotIn(name, body)

    def test_source_has_no_guest_provider_or_key_generation_interface(self):
        text = SOURCE.read_text()
        for name in ('private_guest_command', 'direct_guest_python', 'providerOriginal', 'create_oci_sdk_fixture_key'):
            self.assertNotIn(name, text)
        self.assertIn("'sign-clock-resolution'", text)
        self.assertIn("'--reviewer-seed'", text)

    def test_owned_signer_cleanup_reaps_or_preserves_unknown(self):
        child = MagicMock()
        child.poll.return_value = None
        child.returncode = -15
        with patch.object(reviewer.time, 'monotonic', return_value=10):
            settled = reviewer.stop_clock_signer(child, 13)
        self.assertEqual(settled, {'waitObserved': True, 'exitCode': -15})
        child.terminate.assert_called_once()
        child.kill.assert_not_called()
        child.wait.assert_called_once_with(timeout=0.2)

        child = MagicMock()
        child.poll.return_value = None
        child.wait.side_effect = reviewer.subprocess.TimeoutExpired('owned', 1)
        with patch.object(reviewer.time, 'monotonic', return_value=13):
            settled = reviewer.stop_clock_signer(child, 13)
        self.assertEqual(settled, {'waitObserved': False, 'exitCode': None})
        child.kill.assert_called_once()
        self.assertEqual([call.kwargs['timeout'] for call in child.wait.call_args_list], [0, 0])

    def test_cleanup_reserve_refuses_launch_without_original_time(self):
        with patch.object(reviewer.time, 'monotonic', return_value=10), \
                patch.object(reviewer.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError):
                reviewer.sign_clock_plan(['opaque-current-cli'], MagicMock(), 12)
        launch.assert_not_called()
        self.assertEqual(reviewer.CLEANUP_SECONDS, adapter._CLOCK_REVIEW_CLEANUP_SECONDS)

    def test_signer_exception_still_runs_owned_cleanup_and_retains_wait(self):
        child = MagicMock(pid=7)
        owner = MagicMock()
        owner.__truediv__.return_value.read_text.return_value = '7 (signer) S 1 7 ' + ' '.join(['0'] * 16 + ['11'])
        owner.stat.return_value.st_uid = 2000
        proc = MagicMock()
        proc.__truediv__.return_value = owner
        settled = {'waitObserved': True, 'exitCode': -15}
        with patch.object(reviewer.time, 'monotonic', return_value=10), \
                patch.object(reviewer, 'Path', return_value=proc), \
                patch.object(reviewer.os, 'getuid', return_value=1000), \
                patch.object(reviewer.os, 'chmod'), patch.object(reviewer.os, 'fsync'), \
                patch.object(reviewer.os, 'fstat', return_value=MagicMock(st_size=0)), \
                patch.object(reviewer.subprocess, 'Popen', return_value=child) as launch, \
                patch.object(reviewer, 'stop_clock_signer', return_value=settled) as cleanup, \
                patch.object(reviewer, 'write_new') as retain:
            with self.assertRaises(ValueError):
                reviewer.sign_clock_plan(['opaque-current-cli'], MagicMock(), 20)
        self.assertNotIn('start_new_session', launch.call_args.kwargs)
        cleanup.assert_called_once_with(child, 20)
        record = json.loads(retain.call_args.args[1])
        self.assertTrue(record['waitObserved'])
        self.assertEqual(record['exitCode'], -15)
        self.assertIsNone(record['ownedProcess'])

    def test_reviewer_termination_cancels_and_keeps_signer_in_owned_group(self):
        original = reviewer.termination_requested
        try:
            reviewer.request_termination(15, None)
            with patch.object(reviewer.subprocess, 'Popen') as launch:
                with self.assertRaises(ValueError):
                    reviewer.sign_clock_plan(['opaque-current-cli'], MagicMock(), 100)
                launch.assert_not_called()
        finally:
            reviewer.termination_requested = original
        tree = ast.parse(SOURCE.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'sign_clock_plan')
        self.assertNotIn('start_new_session', ast.get_source_segment(SOURCE.read_text(), function))
        self.assertIn('finally:', ast.get_source_segment(SOURCE.read_text(), function))

    def test_parent_cleanup_signals_only_exact_owned_group(self):
        child = MagicMock(pid=7)
        child.returncode = None
        fields = ['S', '1', '7'] + ['0'] * 16 + ['11']
        owner = MagicMock()
        owner.__truediv__.return_value.read_text.return_value = '7 (reviewer) ' + ' '.join(fields)
        owner.stat.return_value.st_uid = 1000
        root = MagicMock()
        root.__truediv__.return_value = owner
        process = {'pid': 7, 'startTicks': '11', 'uid': 1000}
        def waited(**unused):
            child.returncode = -15
        child.wait.side_effect = waited
        with patch.object(adapter, 'Path', return_value=root), \
                patch.object(adapter.time, 'monotonic', return_value=10), \
                patch.object(adapter.os, 'killpg') as signal_group:
            result = adapter._stop_clock_review_group(child, process, 13)
        signal_group.assert_called_once_with(7, adapter.signal.SIGTERM)
        self.assertTrue(result['reviewerWaitObserved'])
        self.assertNotIn('signerDrain', result)

        child.returncode = None
        process['startTicks'] = '12'
        with patch.object(adapter, 'Path', return_value=root), patch.object(adapter.os, 'killpg') as signal_group:
            with self.assertRaises(ValueError):
                adapter._stop_clock_review_group(child, process, 13)
        signal_group.assert_not_called()

    def test_missing_signer_receipt_does_not_claim_drain(self):
        with patch.object(adapter.os, 'open', side_effect=FileNotFoundError):
            result = adapter._clock_signer_wait_record(Path('unused-private-sign-result.json'), 7)
        self.assertEqual(result, {'signerWaitObserved': False, 'signerExitCode': None, 'signerDrain': 'unknown'})

    def test_orphan_cleanup_refuses_unbound_group_before_pidfd_or_signal(self):
        import stat
        body = encode({'pid': 8, 'startTicks': '11', 'uid': 1000, 'processGroup': 99, 'reviewerPid': 7})
        metadata = MagicMock(st_mode=stat.S_IFREG | 0o600, st_uid=1000, st_nlink=1,
            st_size=len(body), st_dev=1, st_ino=2, st_mtime_ns=3)
        source = MagicMock()
        source.read.return_value = body
        opened = MagicMock()
        opened.__enter__.return_value = source
        path = MagicMock()
        path.lstat.return_value = metadata
        with patch.object(adapter.os, 'open', return_value=5), \
                patch.object(adapter.os, 'fdopen', return_value=opened), \
                patch.object(adapter.os, 'fstat', return_value=metadata), \
                patch.object(adapter.os, 'getuid', return_value=1000), \
                patch.object(adapter.os, 'pidfd_open') as pidfd, \
                patch.object(adapter.signal, 'pidfd_send_signal') as send:
            result = adapter._stop_clock_signer_after_reviewer(path, 7, 13)
        pidfd.assert_not_called()
        send.assert_not_called()
        self.assertEqual(result['orphanSignerTerminalState'], 'unknown')

    def test_cleanup_retention_preserves_primary_and_fails_positive_path(self):
        child, error = MagicMock(), MagicMock()
        child.stdin.close.side_effect = OSError('controlled close failure')
        error.flush.side_effect = OSError('controlled flush failure')
        primary = RuntimeError('controlled original deadline')
        retained = MagicMock(side_effect=OSError('controlled retention failure'))
        with patch.object(adapter, 'retain_direct_flow', retained, create=True), \
                patch.object(adapter.os, 'fsync', side_effect=OSError('controlled fsync failure')), \
                patch.object(adapter.os, 'fstat', side_effect=OSError('controlled stat failure')):
            with self.assertRaises(RuntimeError) as raised:
                try:
                    raise primary
                finally:
                    adapter._retain_clock_review_cleanup(child, error, {'version': 1}, primary)
            self.assertIs(raised.exception, primary)
            self.assertEqual(str(primary), 'controlled original deadline')
            self.assertIn('owned reviewer cleanup retention failed:', primary.__notes__[0])
            self.assertNotIn('controlled retention failure', primary.__notes__[0])
            self.assertIsNone(retained.call_args.args[1]['stderrBytes'])
            with self.assertRaisesRegex(RuntimeError, 'cleanup retention failed'):
                adapter._retain_clock_review_cleanup(child, error, {'version': 1}, None)
        self.assertEqual(child.stdout.close.call_count, 2)

        closing = MagicMock()
        closing.close.side_effect = OSError('controlled final stream close failure')
        with patch.object(adapter.os, 'fdopen', return_value=closing):
            with self.assertRaises(RuntimeError) as raised:
                with adapter._clock_review_error_stream(5):
                    raise primary
            self.assertIs(raised.exception, primary)
            with self.assertRaisesRegex(RuntimeError, 'error-stream close failed'):
                with adapter._clock_review_error_stream(5):
                    pass


if __name__ == '__main__':
    unittest.main()

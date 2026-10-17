"""Synthetic source-formula tests; no compiled runtime availability is asserted."""

import hashlib
import ast
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import contextmanager
import package_context

from producer_inputs import PAIRS, commitments


class ProducerInputs(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory()
        self.addCleanup(self.owner.cleanup)
        self.source = Path(self.owner.name)

    def source_pair(self, role):
        adapter, observer = [self.source / value for value in PAIRS[role]]
        adapter.parent.mkdir(parents=True, exist_ok=True)
        adapter.write_bytes(b'synthetic adapter source')
        observer.write_text('\n'.join(f'include_bytes!("{value.name}")'
                                      for value in (adapter, observer)))
        return adapter, observer

    def test_absent_or_unselected_client_stays_unavailable(self):
        self.assertEqual(commitments(self.source, None), {'sdk': None, 'client': None})
        self.source_pair('client')
        self.assertIsNone(commitments(self.source, None)['client'])

    def test_exact_synthetic_formula_and_changed_input(self):
        adapter, observer = self.source_pair('sdk')
        self.source_pair('client')
        selected = {'file': 'synthetic selected artifact; not runtime proof'}
        measured = commitments(self.source, selected)
        self.assertEqual(measured['sdk'], hashlib.sha256(adapter.read_bytes() + observer.read_bytes()).hexdigest())
        self.assertIsNotNone(measured['client'])
        adapter.write_bytes(b'changed synthetic source')
        self.assertNotEqual(commitments(self.source, selected)['sdk'], measured['sdk'])

    def test_context_requires_actual_artifact_and_exact_source_commitments(self):
        self.source_pair('sdk')
        self.source_pair('client')
        artifact = self.source / 'synthetic-client'
        artifact.write_bytes(b'synthetic compiled artifact, not runtime proof')
        client = {'file': str(artifact), 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  'byteSize': str(artifact.stat().st_size)}
        selected = {'runtimeSource': str(self.source), 'clientExecutable': client,
                    'producerSha256': commitments(self.source, client)}
        library = Path(__file__).parent
        @contextmanager
        def fixture_artifact(path):
            with Path(path).open('rb') as stream:
                yield stream
        def fixture_source(path, maximum=package_context.MAX_CODE):
            raw = Path(path).read_bytes()
            if len(raw) > maximum:
                raise ValueError('Synthetic fixture exceeds source bound')
            return raw
        # Installed custody remains independently checked by the real reader.
        # These synthetic readers exercise the source/artifact joining predicate.
        with patch.object(package_context, 'installed_bytes', fixture_source), \
                patch.object(package_context, 'open_installed', fixture_artifact):
            package_context.validate_producers(selected, library)
            selected['producerSha256']['sdk'] = '0' * 64
            with self.assertRaises(ValueError):
                package_context.validate_producers(selected, library)
            selected['producerSha256'] = commitments(self.source, client)
            artifact.write_bytes(b'substituted synthetic artifact')
            with self.assertRaises(ValueError):
                package_context.validate_producers(selected, library)

    def test_unsupported_or_partial_source_refuses(self):
        adapter, observer = self.source_pair('sdk')
        observer.write_bytes(b'unsupported source formula')
        with self.assertRaises(ValueError):
            commitments(self.source, None)
        self.source_pair('sdk')
        adapter.unlink()
        with self.assertRaises(FileNotFoundError):
            commitments(self.source, None)


class NativeSourceFormula(unittest.TestCase):
    def test_known_old_and_factored_producer_formulas(self):
        source = Path(__file__).parent / 'native_auth.py'
        tree = ast.parse(source.read_text())
        functions = [node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == 'native_handler_source_sha256']
        self.assertEqual(len(functions), 1)
        namespace = {'Path': Path, 'digest': lambda raw: hashlib.sha256(raw).hexdigest()}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
        selected = namespace['native_handler_source_sha256']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handler = root / 'crates/aos-hub/src'
            (handler / 'server').mkdir(parents=True)
            (handler / 'server.rs').write_bytes(b'synthetic handler')
            observation = handler / 'server/hybrid_observation.rs'
            observation.write_bytes(b'digest.update(include_bytes!("../server.rs"));\n'
                                    b'digest.update(include_bytes!("hybrid_observation.rs"));\n')
            old = (handler / 'server.rs').read_bytes() + observation.read_bytes()
            self.assertEqual(selected(root), hashlib.sha256(old).hexdigest())
            (handler / 'server/body_frames.rs').write_bytes(b'synthetic frame counter')
            # An unrelated file does not silently widen the old formula.
            self.assertEqual(selected(root), hashlib.sha256(old).hexdigest())
            observation.write_bytes(observation.read_bytes()
                                    + b'digest.update(include_bytes!("body_frames.rs"));\n')
            complete = ((handler / 'server.rs').read_bytes() + observation.read_bytes()
                        + (handler / 'server/body_frames.rs').read_bytes())
            self.assertEqual(selected(root), hashlib.sha256(complete).hexdigest())
            observation.write_bytes(b'unsupported formula')
            with self.assertRaises(ValueError):
                selected(root)


if __name__ == '__main__':
    unittest.main()

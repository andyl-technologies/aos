"""Confined source extraction regressions against the selected runtime."""

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('extractor', ROOT / 'extract.py')
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


class ExtractionTests(unittest.TestCase):
    def test_current_source_matches_selected_expressions(self):
        runtime = Path(sys.argv[1])
        source = (runtime / 'crates/aos-hub-core/src/web/console/handlers.rs').read_text()
        template, _ = extractor.browser_expression(source)
        expected = json.loads((ROOT / 'fixtures/runtime-provenance.json').read_bytes())['browserSource']
        self.assertEqual(extractor.sha(template), expected['templateSha256'])
        serializer = (runtime / 'crates/aos-hub-core/src/service/publication_manifest.rs').read_text()
        expression = extractor.manifest_expression(serializer)
        self.assertIn('serde_json::to_vec(&canonical)', expression)
        self.assertIn('&object.media_type', expression)

    def test_unsupported_browser_shape_and_escapes_refuse(self):
        source = (Path(sys.argv[1]) / 'crates/aos-hub-core/src/web/console/handlers.rs').read_text()
        for altered in [source.replace('let html = format!(', 'let html = another!('),
                        source.replace('<!doctype html>', r'\u{41}'),
                        source.replace('{csrf}', '{unsupported}'),
                        source.replace('    );\n    (', '        , extra\n    );\n    (', 1)]:
            with self.assertRaises(ValueError):
                extractor.browser_expression(altered)

    def test_later_template_cannot_replace_management_expression(self):
        source = (Path(sys.argv[1]) / 'crates/aos-hub-core/src/web/console/handlers.rs').read_text()
        altered = source.replace('let html = format!(', 'let html = another!(', 1)
        later = source.split('pub(crate) async fn management_app(', 1)[1]
        later = later[:later.index('\n}\n') + 3]
        with self.assertRaises(ValueError):
            extractor.browser_expression(altered + '\nfn unrelated(' + later)

    def test_changed_or_ambiguous_serializer_refuses(self):
        source = (Path(sys.argv[1]) / 'crates/aos-hub-core/src/service/publication_manifest.rs').read_text()
        for altered in [source + source,
                        source.replace('objects: &[pb::RegistryPublicationObjectInput]', 'objects: &[String]'),
                        source.replace('let canonical = objects', 'let canonical = "changed"; let x = objects')]:
            with self.assertRaises(ValueError):
                extractor.manifest_expression(altered)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])

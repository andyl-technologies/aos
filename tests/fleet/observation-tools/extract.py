"""Extract two confined production expressions before compiling observation tools.

Unsupported source shapes refuse rather than silently switching serializers or
browser templates. Runtime evidence remains separate from helper build evidence.
"""

import hashlib
import json
from pathlib import Path
import re
import sys


SLOTS = {'title', 'csrf', 'brand', 'tagline', 'announcement', 'tos_url',
         'privacy_url', 'support_url', 'app_version', 'container_gc_enabled',
         'asset_version', 'css', 'bootstrap'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def browser_expression(source):
    """Decode the single ordinary Rust string in the management HTML expression."""
    marker = 'pub(crate) async fn management_app('
    if source.count(marker) != 1:
        raise ValueError('Management handler is ambiguous')
    handler = source.split(marker, 1)[1]
    ending = re.search(r'(?m)^}\n', handler)
    if ending is None:
        raise ValueError('Management handler boundary is unsupported')
    handler = handler[:ending.end()]
    match = re.search(r'\blet html = format!\(\s*"', handler)
    if match is None:
        raise ValueError('Management template shape is unsupported')
    start = match.end() - 1
    position = start + 1
    output = []
    escapes = {'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}
    while position < len(handler):
        character = handler[position]
        position += 1
        if character == '"':
            break
        if character != '\\':
            output.append(character)
            continue
        if position == len(handler):
            raise ValueError('Incomplete Rust escape')
        escaped = handler[position]
        position += 1
        if escaped == '\n':
            while position < len(handler) and handler[position] in ' \t\r\n':
                position += 1
        elif escaped in escapes:
            output.append(escapes[escaped])
        else:
            raise ValueError('Unsupported Rust escape')
    else:
        raise ValueError('Unterminated template')
    if not re.match(r'\s*\);', handler[position:]):
        raise ValueError('Additional format arguments are unsupported')
    template = ''.join(output)
    slots = re.findall(r'\{([^{}]+)\}', template)
    if set(slots) != SLOTS or any(char in re.sub(r'\{[^{}]+\}', '', template) for char in '{}'):
        raise ValueError('Template slots differ')
    return template.encode(), handler[match.start():position].encode()


def manifest_expression(source):
    """Select the production digest function without rewriting its body."""
    marker = 'fn registry_publication_manifest_chunk_digest('
    if source.count(marker) != 1:
        raise ValueError('Manifest serializer is ambiguous')
    start = source.index(marker)
    opening = source.index('{', start)
    signature = source[start:opening]
    if not re.fullmatch(r'fn registry_publication_manifest_chunk_digest\(\s*objects: '
                        r'&\[pb::RegistryPublicationObjectInput\],\s*\) '
                        r'-> Result<String, RpcError>\s*', signature):
        raise ValueError('Manifest serializer signature differs')
    depth = 1
    position = opening + 1
    while depth and position < len(source):
        character = source[position]
        # This selected expression has no literal or comment grammar. A future
        # expression using those constructs needs an explicit extractor review.
        if character in '\"\'' or source[position:position + 2] in ('//', '/*'):
            raise ValueError('Unsupported serializer lexical shape')
        depth += (character == '{') - (character == '}')
        position += 1
    if depth:
        raise ValueError('Unbalanced serializer')
    return source[start:position]


def extract(runtime, output, provenance, contract):
    runtime, output = Path(runtime), Path(output)
    handler_path = runtime / 'crates/aos-hub-core/src/web/console/handlers.rs'
    handler = handler_path.read_bytes()
    template, expression = browser_expression(handler.decode())
    selected = provenance['browserSource']
    if (sha(handler) != selected['handlerSourceSha256']
            or sha(template) != selected['templateSha256']):
        raise ValueError('Runtime browser source differs')
    for name, key in [('JS', 'consoleJsSha256'), ('WASM', 'consoleWasmSha256'),
                      ('CSS', 'consoleCssSha256')]:
        if sha(Path(contract['cargoEnv']['AOS_HUB_CONSOLE_' + name]).read_bytes()) != selected[key]:
            raise ValueError('Selected Native console artifact differs')
    manifest_path = runtime / 'crates/aos-hub-core/src/service/publication_manifest.rs'
    manifest = manifest_path.read_bytes()
    function = manifest_expression(manifest.decode())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'browser').mkdir(exist_ok=True)
    (output / 'browser/template.txt').write_bytes(template)
    record = {'sourceFile': str(handler_path.relative_to(runtime)), 'sourceSha256': sha(handler),
              'templateSha256': sha(template), 'sourceExpressionSha256': sha(expression)}
    (output / 'browser/template-source.json').write_text(json.dumps(record, indent=2) + '\n')
    imports = ('//! Exact source-extracted production manifest-page serializer.\n\n'
               'use aos_hub_core::service::RpcError;\nuse aos_proto_types as pb;\n'
               'use sha2::{Digest as _, Sha256};\n\n')
    forwarding = ('\n\npub(super) fn digest(objects: &[pb::RegistryPublicationObjectInput]) '
                  '-> Result<String, RpcError> {\n    registry_publication_manifest_chunk_digest(objects)\n}\n')
    (output / 'manifest_digest.rs').write_text(imports + function + forwarding)
    (output / 'extraction.json').write_text(json.dumps({
        'browser': record, 'manifest': {'sourceFile': str(manifest_path.relative_to(runtime)),
                                      'sourceSha256': sha(manifest), 'expressionSha256': sha(function.encode())},
    }, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 5:
        raise SystemExit('Expected runtime source, output, runtime provenance and Native contract')
    extract(sys.argv[1], sys.argv[2], json.loads(Path(sys.argv[3]).read_bytes()),
            json.loads(Path(sys.argv[4]).read_bytes()))

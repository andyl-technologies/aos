"""Checks Kbuild's actual source/dependency records against selected native roles.

Ordinary generated configuration headers are Kbuild inputs, not published native
source roles. Every observed x86 KVM header, common KVM include fragment and
Crucible declaration must belong to this frozen source catalog. Required
original roles are exact path tokens, never substring matches.
"""

import hashlib
import json
import posixpath
from pathlib import Path
import shlex
import sys


def parse_record(body, key):
    category, target = key.split('_', 1)
    matches = []
    prefixes = {}
    for index, line in enumerate(body.splitlines()):
        if ' := ' not in line:
            continue
        variable = line.split(' := ', 1)[0]
        if not variable.startswith(category + '_'):
            continue
        recorded = variable[len(category) + 1:]
        # KVM's Kbuild owns shared objects through arch/x86/kvm/../../../virt.
        # This exact physical alias is accepted; a different target is not.
        if not recorded.startswith('/') and posixpath.normpath(recorded) == target:
            matches.append(index)
            prefixes[index] = variable + ' := '
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous original Kbuild record: ' + key)
    lines = body.splitlines()
    index = matches[0]
    value = lines[index][len(prefixes[index]):]
    while value.endswith('\\'):
        index += 1
        value = value[:-1] + ' ' + lines[index].strip()
    # Only Kbuild's configuration-existence expressions may be omitted.
    import re
    value = re.sub(r'\$\(wildcard include/config/[A-Za-z0-9_]+\)', '', value)
    if '$' in value:
        raise ValueError('Unsupported dependency expression')
    return shlex.split(value)


def verify(root, target, required, catalog):
    object_path = Path(target)
    record = root / object_path.parent / ('.' + object_path.name + '.cmd')
    body = record.read_text()
    source = parse_record(body, 'source_' + target)
    if (len(source) != 1 or posixpath.normpath(source[0]) !=
            target.removesuffix('.o') + '.c'):
        raise ValueError('Different original native source TU')
    command = parse_record(body, 'savedcmd_' + target)
    if '-Werror' not in command:
        raise ValueError('Native strict compiler flags changed')
    tokens = list(source)
    tokens += parse_record(body, 'deps_' + target)
    selected = set()
    for token in tokens:
        actual = Path(token)
        if not actual.is_absolute():
            actual = root / actual
        actual = actual.resolve()
        try:
            relative = actual.relative_to(root).as_posix()
        except ValueError:
            raise ValueError('Native compiler selected an external source input')
        native = (
            (relative.startswith('arch/x86/kvm/') and
             (relative.endswith('.h') or relative.endswith('.inc.c'))) or
            (relative.startswith('virt/kvm/') and relative.endswith('.inc.c')) or
            (relative.startswith('include/linux/kvm_crucible_') and
             relative.endswith('.h'))
        )
        if native and relative not in catalog:
            raise ValueError('Unknown native dependency role: ' + relative)
        if relative in catalog:
            source = actual.read_bytes()
            expected = catalog[relative]
            if (len(source) != expected['bytes'] or
                    hashlib.sha256(source).hexdigest() != expected['sha256']):
                raise ValueError('Changed selected native dependency: ' + relative)
            selected.add(relative)
    if not set(required) <= selected:
        raise ValueError('Missing original source roles: ' + str(sorted(set(required) - selected)))
    object_body = (root / target).read_bytes()
    return {'object': target, 'object_bytes': len(object_body),
            'object_sha256': hashlib.sha256(object_body).hexdigest(),
            'compiler_argv': command, 'selected_native_roles': sorted(selected),
            'dependency_record_sha256': hashlib.sha256(record.read_bytes()).hexdigest()}


def main():
    if sys.flags.optimize:
        raise RuntimeError('Optimized native dependency checking refuses')
    root = Path(sys.argv[1]).resolve()
    target = sys.argv[2]
    here = Path(__file__).parent
    inventory = json.loads((here / 'source-inventory.json').read_text())
    catalog = {row['path']: row['completed'] for row in inventory['files']}
    required = json.loads((here / 'native-inputs.json').read_text())[target]
    report = verify(root, target, required, catalog)
    (root / ('pic-' + Path(target).name + '.inputs.json')).write_text(
        json.dumps(report, indent=2) + '\n')
    print('Actual native source/dependency roles verified: ' + target)


if __name__ == '__main__':
    main()

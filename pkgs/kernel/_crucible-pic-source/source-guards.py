"""Rechecks exact object-source inputs and the retained unsupported board cut."""

from pathlib import Path
import json
import posixpath
import re
import sys

from importlib.util import module_from_spec, spec_from_file_location


def verify_quoted_closure(root, rows):
    """Checks literal native includes before any compiler effects."""
    catalog = {row['path'] for row in rows}
    pending = list(catalog)
    visited = set()
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        visited.add(relative)
        body = (root / relative).read_text()
        for match in re.finditer(r'^\s*#\s*include\s+"([^"\n]+)"', body, re.M):
            include = match.group(1)
            candidates = [
                posixpath.normpath(str(Path(relative).parent / include)),
                posixpath.normpath('include/' + include),
                posixpath.normpath('arch/x86/include/' + include),
                posixpath.normpath('arch/x86/include/generated/' + include),
            ]
            selected = next((path for path in candidates
                             if not path.startswith('../') and
                             (root / path).is_file()), None)
            if selected is None:
                raise ValueError('Missing literal source include: ' +
                                 relative + ' -> ' + include)
            if ((selected.startswith('arch/x86/kvm/') or
                 selected.startswith('virt/kvm/')) and
                    selected not in catalog):
                raise ValueError('Unpublished native include role: ' + selected)
            if selected in catalog:
                pending.append(selected)


def main():
    if sys.flags.optimize:
        raise RuntimeError('Optimized source checking refuses')
    root = Path(sys.argv[1]).resolve()
    here = Path(__file__).parent
    spec = spec_from_file_location('pic_source', here / 'apply-source.py')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    inventory = json.loads((here / 'source-inventory.json').read_text())
    phase = sys.argv[2] if len(sys.argv) == 3 else 'completed'
    if phase not in ('completed', 'eoi'):
        raise ValueError('Unknown source checkpoint')
    module.verify(root, inventory['files'], phase)
    # A later additive role must be absent at the preceding checkpoint; it
    # enters the complete quoted-include census only after exact application.
    present = [row for row in inventory['files'] if row[phase] is not None]
    verify_quoted_closure(root, present)
    if 'CONFIG_WERROR=y' not in (root / '.config').read_text().splitlines():
        raise ValueError('Original strict AOS kernel configuration changed')
    clock = (root / 'arch/x86/kvm/crucible-clock.c').read_text()
    refused = 'if (irqchip_in_kernel(kvm) || !list_empty(&kvm->devices))\n\t\t\tresult = -EBUSY;'
    if clock.count(refused) != 1:
        raise ValueError('Unsupported native FirstBegin IRQchip prerequisite changed')
    print('Exact object-source inputs, Werror and unsupported board prerequisite retained')


if __name__ == '__main__':
    main()

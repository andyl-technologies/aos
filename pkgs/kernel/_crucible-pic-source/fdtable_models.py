"""Binds the closed FD cases to actual PS source for the PIC check facility.

This module only emits source and compiler proposals. The existing check-models
executor owns compiler/control results and the original resource reservation.
Kernel/RCU/allocator peers in the template remain explicitly modeled.
"""

from pathlib import Path
import hashlib
import json
import re


def measure(path):
    body = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
            'bytes': len(body)}


def body_end(text, start):
    depth = 0
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    for match in tokens.finditer(text, start):
        if match[0] == '{':
            depth += 1
        elif match[0] == '}':
            depth -= 1
            if not depth:
                return match.end()
    raise ValueError('Unclosed original source body')


def function(text, name):
    pattern = re.compile(
        r'^(?:static\s+)?(?:(?:__\w+|inline|noinline)\s+)*(?:const\s+)?'
        r'(?:struct\s+\w+|unsigned\s+int|void|bool|u64|u32|int|size_t)\s*\**\s*'
        r'(?:noinline\s+)?' + re.escape(name) + r'\s*\([^{};]*?\)\s*\{', re.M)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise ValueError('Nonunique original source function: ' + name)
    match = matches[0]
    return text[match.start():body_end(text, match.end() - 1)]


def record(text, name):
    matches = list(re.finditer(r'struct\s+' + re.escape(name) + r'\s*\{', text))
    if len(matches) != 1:
        raise ValueError('Nonunique original source record: ' + name)
    match = matches[0]
    end = body_end(text, match.end() - 1)
    return text[match.start():text.index(';', end) + 1]


def portable_header(text):
    return '\n'.join(line for line in text.splitlines()
                     if not line.startswith('#') or
                     (line.startswith('#define CRUCIBLE_') and
                      not line.startswith('#define _LINUX_')))


def generate(source, compiler, root, fixtures):
    catalog = json.loads((fixtures / 'complete-source-catalog.json').read_text())
    for row in catalog['files']:
        path = source / row['path']
        actual = measure(path)
        if (path.is_symlink() or
                {key: actual[key] for key in ['sha256', 'bytes']} != row['identity']):
            raise ValueError('Changed selected source role: ' + row['path'])

    bindings = []

    def text(role):
        path = source / role
        bindings.append({'kind': 'complete-role', 'role': role, **measure(path)})
        return path.read_text()

    def functions(role, names):
        original = text(role)
        selected = []
        for name in names:
            body = function(original, name)
            bindings.append({'kind': 'function', 'role': role, 'name': name,
                             'sha256': hashlib.sha256(body.encode()).hexdigest(),
                             'bytes': len(body.encode())})
            selected.append(body)
        return '\n\n'.join(selected)

    allocator = 'mm/crucible_allocator.c'
    resource = 'virt/kvm/crucible-original-kernel-resource.inc.c'
    native = 'fs/file.c'
    resource_text = text(resource)
    selections = {
        'ALLOCATOR_HEADER': portable_header(text('include/linux/crucible_allocator.h')),
        'FD_HEADER': portable_header(text('include/linux/crucible_fdtable.h')),
        'FD_TYPES': '\n\n'.join(record(text('include/linux/fdtable.h'), name)
                                 for name in ['fdtable', 'files_struct']),
        'RESOURCE_TYPES': '\n\n'.join([
            record(text('include/uapi/linux/kvm.h'), 'kvm_crucible_kernel_resource_policy'),
            record(resource_text, 'kvm_crucible_resource_allocation'),
            record(resource_text, 'kvm_crucible_kernel_resource_context'),
        ]),
        'ALLOCATOR_CORE': functions(allocator, [
            'crucible_allocator_actor', 'crucible_allocator_cleanup_observer',
            'crucible_allocator_current', 'crucible_allocator_enter', 'crucible_allocator_leave',
        ]),
        'RETIREMENT': text('mm/crucible_allocator_retirement.inc.c'),
        'ALLOCATOR_DISPATCH': functions(allocator, [
            'crucible_allocator_slab_reserve', 'crucible_allocator_slab_complete',
        ]),
        'FD_ENGINE': text('fs/crucible_fdtable.inc.c'),
        'RESOURCE_SINKS': functions(resource, [
            'crucible_resource_allocator_current', 'crucible_resource_fdtable_growth',
            'crucible_resource_fdtable_retirement', 'crucible_resource_fdtable_files_retirement',
            'crucible_resource_fdtable_slot_retirement',
        ]),
        'SLUB_WRAPPER': functions('mm/slub.c', ['slab_free']),
        'NATIVE_FILES_PUT': functions(native, ['put_files_struct']),
        'NATIVE_FD': functions(native, [
            '__free_fdtable_native', '__free_fdtable', 'free_fdtable_rcu',
            'copy_fd_bitmaps', 'copy_fdtable', 'alloc_fdtable', 'expand_fdtable',
            'expand_files', '__set_close_on_exec', '__set_open_fd', '__clear_open_fd',
            'find_next_fd', 'alloc_fd', '__get_unused_fd_flags', 'get_unused_fd_flags',
            '__put_unused_fd', 'put_unused_fd', 'fd_install_slowpath', 'fd_install',
            'file_close_fd_locked', 'do_dup2',
        ]),
    }
    template = fixtures / 'fdtable-model.c.in'
    body = template.read_text()
    cases = re.findall(r'\trun_case\((\w+)\);', body)
    if len(cases) != 21 or len(set(cases)) != 21:
        raise ValueError('Closed twenty-one-case FD roster changed')
    for name, value in selections.items():
        marker = '@' + name + '@'
        if body.count(marker) != 1:
            raise ValueError('Nonunique source-control marker: ' + name)
        body = body.replace(marker, value)
    if re.search(r'@[A-Z_]+@', body):
        raise ValueError('Unbound source-control marker')

    # An assertions-disabled build cannot stand in for executed controls.
    assertion_guard = '#ifdef NDEBUG\n#error "FD controls require active assertions"\n#endif\n'
    model = root / 'model'
    model.mkdir()
    emitted = model / 'fdtable-source.c'
    emitted.write_text(assertion_guard + body)
    ordinary = model / 'ordinary-fdtable.c'
    ordinary.write_text(assertion_guard + (fixtures / 'ordinary-fdtable.c').read_text())
    commands = []
    for name, path, count in [('fdtable-source', emitted, 21), ('ordinary-fdtable', ordinary, 4)]:
        commands.append({
            'name': name, 'source': measure(path), 'case_count': count,
            'expected_model_returncode': 0, 'expected_assertion': None,
            'expected_assertion_line': None, 'output': str(model / name),
            'argv': [*compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
                     str(path), '-o', str(model / name)],
        })
    (root / 'model-proposal.json').write_text(json.dumps(commands, indent=2) + '\n')
    (root / 'source-bindings.json').write_text(json.dumps({
        'source_only': True, 'catalog': measure(fixtures / 'complete-source-catalog.json'),
        'template': measure(template), 'case_names': cases,
        'ordinary': measure(fixtures / 'ordinary-fdtable.c'), 'bindings': bindings,
        'runtime_qualification': False,
    }, indent=2) + '\n')

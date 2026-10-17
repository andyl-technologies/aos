"""Extracts original EOI/LOW/ACK bodies without executing native code."""

from pathlib import Path
import hashlib
import json
import re
import sys
import shlex


HERE = Path(__file__).resolve().parent
SOURCE = Path(sys.argv[1]).resolve()
COMPILER = shlex.split(sys.argv[2])


def read(relative):
    return (SOURCE / relative).read_text()


def function(body, signature):
    start = body.rindex(signature)
    opening = body.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (body[end] == '{') - (body[end] == '}')
        end += 1
    return body[start:end]


def once(body, old, new):
    if body.count(old) != 1:
        raise RuntimeError('Nonunique source extraction/control anchor')
    return body.replace(old, new)


def measure(path):
    body = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
            'bytes': len(body)}


if sys.flags.optimize:
    raise RuntimeError('Optimized source generation refuses')
output = Path(sys.argv[3]).resolve()
output.mkdir()
pic = read('arch/x86/kvm/i8259.c')
irq = read('arch/x86/kvm/irq.h')
pit_header = read('arch/x86/kvm/i8254.h')
kernel = read('include/linux/kvm_host.h')
ancestry = read('arch/x86/kvm/crucible-pit-ancestry.inc.c')
types = function(kernel, 'struct kvm_crucible_pit_irq_birth {') + ';\n'
types += function(irq, 'struct kvm_kpic_state {') + ';\n'
types += irq[irq.index('#define CRUCIBLE_PIC_PIT_PENDING'):irq.index('struct kvm_pic {')]
types += function(irq, 'struct kvm_pic {') + ';\n'
pit_types = pit_header[pit_header.index('#define KVM_CRUCIBLE_PIT_PENDING'):
                       pit_header.index('struct kvm_kpit_state {')]
pit_types += '''
/* Device/worker containers are modeled peers; actual finite journals above
 * retain every native field without rewriting signed/native declarations. */
struct kvm_pit {
    struct kvm *kvm;
    struct { int reinject; struct kvm_crucible_pit_journal crucible; } pit_state;
    struct kthread_worker *worker;
    struct kthread_work expired;
};
'''
peers = (HERE / 'eoi-peers.c.in').read_text()
peers = once(peers, '@PIT_TYPES@', types + pit_types)
declarations = '''
static void pic_irq_request(struct kvm *kvm, int level);
int kvm_crucible_pic_set_pit_irq(struct kvm_kernel_irq_routing_entry *e,
    struct kvm *kvm, int source, int level, bool line_status,
    const struct kvm_crucible_pit_irq_birth *original);
static bool pic_pit_eoi_complete_locked(struct kvm_pic *pic,
    const struct kvm_crucible_pit_irq_birth *low);
'''
pit_functions = '\n\n'.join(function(ancestry, signature) for signature in [
    'static bool pit_native_selected(', 'static bool pit_native_live_locked(',
    'static bool pit_native_run_locked(', 'static bool pit_native_birth_locked(',
    'static bool pit_native_schedule_locked(',
    'bool kvm_arch_crucible_pit_irq_birth_live_locked(',
])
pic_functions = '\n\n'.join(function(pic, signature) for signature in [
    'static void pic_lock(', 'static void pic_unlock(',
    'static inline int pic_set_irq1(', 'static inline int get_priority(',
    'static int pic_get_irq(', 'static void pic_update_irq(',
    'static void pic_irq_request(', 'int kvm_pic_set_irq(',
    'static u64 pic_pit_geometry(', 'static bool pic_pit_original_equal(',
    'int kvm_crucible_pic_set_pit_irq(',
])
notice = pic[:pic.index('#define pr_fmt')]
body = '\n\n'.join([
    notice, '/* Combined GPL-2.0-only model with complete copied MIT notice. */',
    peers,
    function(read('arch/x86/kvm/crucible-irq-device-access.h'),
             'struct crucible_irq_device_lease {') + ';',
    '\n\n'.join(function(read('arch/x86/kvm/crucible-irq-device-access.h'), signature)
                for signature in ['static bool crucible_irq_device_selected(',
                                  'static bool crucible_irq_device_run_locked(',
                                  'static bool crucible_irq_device_begin(',
                                  'static int crucible_irq_device_finish(']), declarations,
    pit_functions, pic_functions, read('arch/x86/kvm/crucible-pit-pic-ack.inc.c'),
    read('arch/x86/kvm/crucible-pic-eoi.inc.c'),
    function(pic, 'static bool pic_pit_controller_write_safe_locked('),
    function(pic, 'static int picdev_write('),
    (HERE / 'eoi-setup.c.in').read_text(), (HERE / 'eoi-cases.c.in').read_text(),
])
variants = [('corrected', body, 0)]
controls = [
    ('known-high', 'row->high_known &&', 'true &&'),
    ('locked-geometry', 'row->geometry == pic_pit_geometry(&pic->pics[0]) &&', 'true &&'),
    ('original-target', 'row->target_id == vcpu->vcpu_id &&', 'true &&'),
    ('pending-original', 'journal->awaiting_ack &&', 'true &&'),
    ('original-sequence', 'journal->ack_sequence == row->original.sequence &&', 'true &&'),
    ('original-generation', 'journal->ack_generation == row->original.generation &&', 'true &&'),
    ('original-invocation', 'journal->ack_invocation == row->original.invocation &&', 'true &&'),
    ('finite-eoi', 'pic->crucible_eoi_issued < CRUCIBLE_PIC_PIT_ISSUED;', 'true;'),
]
original = function(body, 'static int pic_pit_original_eoi(')
for name, before, after in controls:
    changed = original.replace(before, after, 1)
    if changed == original:
        raise RuntimeError('Actual original EOI predicate absent')
    variants.append((name, once(body, original, changed), -6))

completion = function(body, 'static bool pic_pit_eoi_complete_locked(')
for name, before in [('pending-result', '!row->eoi_native_known ||'),
                     ('pending-low-tail', '!row->low_tail_known')]:
    replacement = 'false ||' if before.endswith('||') else 'false'
    variants.append((name, once(body, completion,
                               once(completion, before, replacement)), -6))

run = function(body, 'static bool crucible_irq_device_run_locked(')
variants.append(('original-run', once(body, run,
    once(run, 'vcpu->crucible_timer_run_owner == current &&', 'true &&')), -6))

finish = function(body, 'static int pic_pit_eoi_finish(')
variants.append(('finish-row-reconciliation', once(body, finish,
    once(finish, 'row->phase = CRUCIBLE_PIC_PIT_UNKNOWN;', '(void)row;')), -6))
high = function(body, 'int kvm_crucible_pic_set_pit_irq(')
variants.append(('next-high-reuse', once(body, high,
    once(high, '!row->eoi_inflight &&', 'true &&')), -6))

# The exact frozen predecessor is compiled only as a causal negative. Its
# original generic finish releases credit before local row demotion; the new
# final-seam case detects that order at the stopped observer boundary.
previous = (HERE / 'eoi-release-predecessor.inc.c').read_text()
predecessor = once(body, function(body, 'static int pic_pit_original_eoi('),
                   function(previous, 'static int pic_pit_original_eoi('))
predecessor = once(predecessor, finish, '')
variants.append(('original-release-predecessor', predecessor, -6))

controller = function(body, 'static bool pic_pit_controller_write_safe_locked(')
variants.append(('controller-inflight', once(body, controller,
    once(controller, 'pic->crucible_pit[pin].eoi_inflight ||', 'false ||')), -6))
variants.append(('finish-geometry', once(body, finish,
    once(finish, 'row->geometry == pic_pit_geometry(&pic->pics[0]) &&', 'true &&')), -6))

oracles = json.loads((HERE / 'eoi-oracles.json').read_text())
commands = []
for name, source, status in variants:
    path = output / (name + '.c')
    path.write_text(source)
    lexical = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
    definitions = re.findall(r'\bstatic(?:\s+inline)?\s+\w+(?:\s+\w+)?\s+(\w+)\s*\(', lexical)
    counts = {name: len(re.findall(r'\b' + name + r'\s*\(', lexical)) for name in definitions}
    commands.append({'name': name, 'source': measure(path),
                     'expected_returncode': status, 'static_counts': counts,
                     'unreferenced_helpers': [name for name, count in counts.items() if count == 1],
                     'compiler_flags': ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread'],
                     'expected_model_returncode': status,
                     'expected_assertion': oracles[name]['expected_assertion'],
                     'expected_assertion_line': oracles[name]['expected_assertion_line'],
                     'argv': [*COMPILER, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                              '-pthread', str(path), '-o', str(output / name)],
                     'output': str(output / name)})
if len(commands) != 17 or set(oracles) != {row['name'] for row in commands}:
    raise RuntimeError('Closed original EOI control roster changed')
for row in commands:
    assertion = row['expected_assertion']
    if assertion is None:
        continue
    lines = Path(row['source']['path']).read_text().splitlines()
    tail = '\n'.join(lines[row['expected_assertion_line'] - 1:])
    if not tail.lstrip().startswith('assert('):
        raise RuntimeError('Original EOI assertion location changed')
    expression = tail[tail.index('assert(') + 7:tail.index(');')]
    if ' '.join(expression.split()) != assertion:
        raise RuntimeError('Original EOI full assertion changed')
(output / 'model-proposal.json').write_text(json.dumps(commands, indent=2) + '\n')
print('Source proposal generated; no compiler/model/native execution')

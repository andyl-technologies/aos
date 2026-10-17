"""Builds source-identical PIC producer/intack/EXTINT control proposals."""

from pathlib import Path
import sys
import shlex
import hashlib
import json
import re


HERE = Path(__file__).parent
SOURCE = Path(sys.argv[1]).resolve()
COMPILER = shlex.split(sys.argv[2])
ROOT = Path(sys.argv[3]).resolve()
if sys.flags.optimize or not COMPILER:
    raise RuntimeError('Optimized generation or absent source compiler refuses')
ROOT.mkdir()


def once(body, old, new):
    if body.count(old) != 1:
        raise RuntimeError('Control source anchor is not unique')
    return body.replace(old, new)


def function(body, signature):
    start = body.rindex(signature)
    opening = body.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (body[end] == '{') - (body[end] == '}')
        end += 1
    return body[start:end]


def measure(path):
    body = Path(path).read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
            'bytes': len(body)}


source = (SOURCE / 'arch/x86/kvm/i8259.c').read_text()
header = (SOURCE / 'arch/x86/kvm/irq.h').read_text()
kernel_header = (SOURCE / 'include/linux/kvm_host.h').read_text()
injection = (SOURCE / 'arch/x86/kvm/crucible-irq-injection.h').read_text()
device = (SOURCE / 'arch/x86/kvm/crucible-irq-device-access.h').read_text()
peers = (HERE / 'model-peers.c.in').read_text()
types = function(kernel_header, 'struct kvm_crucible_pit_irq_birth {') + ';\n'
types += function(header, 'struct kvm_kpic_state {') + ';\n'
start = header.index('#define CRUCIBLE_PIC_PIT_PENDING')
end = header.index('struct kvm_pic {', start)
types += header[start:end]
types += function(header, 'struct kvm_pic {') + ';\n'
peers = once(peers, 'static struct kvm vm;', types + '\nstatic struct kvm vm;')

native_names = [
    'static void pic_lock(', 'static void pic_unlock(',
    'static inline int pic_set_irq1(', 'static inline int get_priority(',
    'static int pic_get_irq(', 'static void pic_update_irq(',
    'static void pic_irq_request(', 'int kvm_pic_set_irq(',
    'static u64 pic_pit_geometry(', 'static bool pic_pit_original_equal(',
    'int kvm_crucible_pic_set_pit_irq(',
    'static bool pic_pit_consume_begin_locked(',
    'bool kvm_crucible_pic_injection_finish(',
    'void kvm_crucible_pic_injection_failed(',
    'static bool pic_pit_controller_write_safe_locked(',
    'static inline void pic_intack(', 'int kvm_pic_read_irq(',
    'int kvm_crucible_pic_read_irq(',
]
declarations = '''
static void pic_irq_request(struct kvm *kvm, int level);
int kvm_crucible_pic_set_pit_irq(struct kvm_kernel_irq_routing_entry *e,
    struct kvm *kvm, int source, int level, bool line_status,
    const struct kvm_crucible_pit_irq_birth *original);
'''
native = '\n\n'.join(function(source, name) for name in native_names)
lease_struct = function(injection, 'struct crucible_irq_injection_lease {') + ';'
lease = '\n\n'.join(function(injection, name) for name in [
    'static bool crucible_irq_injection_selected(',
    'static bool crucible_irq_injection_run_locked(',
    'static bool crucible_irq_injection_begin(',
    'static int crucible_irq_injection_finish(',
])
x86_header = (SOURCE / 'arch/x86/kvm/x86.h').read_text()
queue = function(x86_header, 'static inline void kvm_queue_interrupt(')
queue = once(queue, '\tvcpu->arch.interrupt.injected = true;',
    '\t/* Modeled native boundary counter; remaining queue body is exact. */\n'
    '\tnative_queues++;\n\tvcpu->arch.interrupt.injected = true;')
get_interrupt = '''
static int kvm_cpu_get_interrupt(struct kvm_vcpu *vcpu)
{
    /* Original PIC routing is the selected modeled boundary; the actual
     * parent irq.c dispatcher and all other producers remain separate. */
    return kvm_crucible_pic_read_irq(vcpu);
}
'''
x86 = (SOURCE / 'arch/x86/kvm/x86.c').read_text()
start = x86.index('\tif (kvm_cpu_has_injectable_intr(vcpu)) {')
end = x86.index('\n\tif (is_guest_mode(vcpu)', start)
architecture = '''
static int architecture_irq_tail(struct kvm_vcpu *vcpu)
{
    int r = 0;
    bool can_inject = true;

    assert(!pthread_mutex_lock(&vcpu->mutex));
''' + x86[start:end] + '''
out:
    assert(!pthread_mutex_unlock(&vcpu->mutex));
    return r < 0 ? r : 0;
}
'''
cases = (HERE / 'model-cases.c.in').read_text()
# Copied MIT portions retain their complete original notice; other extracted
# GPL-2.0-only inputs make this a combined GPL-compatible source test program.
notice = source[:source.index('#define pr_fmt')]
model_scope = '/* Combined source model: GPL-2.0-only inputs and MIT portions. */'
base = '\n\n'.join([notice, model_scope, peers, device, declarations, native, lease_struct,
                       lease, queue, get_interrupt, architecture, cases])
variants = [('corrected', base, 0)]

# Each erasure changes one exact actual native predicate. All controls retain
# the complete positive/negative main and the same Werror flags.
controls = [
    ('original-pit-source', 'int kvm_crucible_pic_set_pit_irq(',
     'kvm_arch_crucible_pit_irq_birth_live_locked(kvm, original) &&', 'true &&', 1),
    ('pending-receiver', 'static bool pic_pit_consume_begin_locked(',
     'row->phase == CRUCIBLE_PIC_PIT_PENDING &&', 'true &&', 1),
    ('known-high', 'static bool pic_pit_consume_begin_locked(',
     'row->high_known &&', 'true &&', 1),
    ('original-generation', 'static bool pic_pit_consume_begin_locked(',
     'row->original.generation == kvm->arch.crucible_clock.window_generation &&',
     'true &&', 1),
    ('original-run', 'static bool pic_pit_consume_begin_locked(',
     'crucible_irq_device_run_locked(kvm, vcpu) &&', 'true &&', 1),
    ('locked-geometry', 'static bool pic_pit_consume_begin_locked(',
     'row->vector == state->irq_base && row->geometry == pic_pit_geometry(state) &&',
     'true &&', 1),
    ('auto-eoi', 'static bool pic_pit_consume_begin_locked(',
     '!state->auto_eoi &&', 'true &&', 1),
    ('slave-cascade', 'static bool pic_pit_consume_begin_locked(',
     '!pic->pics[1].irr && !pic->pics[1].isr', 'true', 1),
    ('queued-vector', 'bool kvm_crucible_pic_injection_finish(',
     'vcpu->arch.interrupt.nr == row->vector &&', 'true &&', 1),
    ('final-pic-disposition', 'static int crucible_irq_injection_finish(',
     'kvm_crucible_pic_injection_failed(vcpu);', '(void)vcpu;', 1),
    ('controller-write', 'static bool pic_pit_controller_write_safe_locked(',
     'return false;', 'return true;', 1),
]
for name, signature, before, after, count in controls:
    original = function(base, signature)
    if original.count(before) < count:
        raise RuntimeError('Erasure source predicate is absent')
    changed = original.replace(before, after, count)
    variants.append((name, once(base, original, changed), -6))

case_anchors = {'original-pit-source': 'birth_live = false;', 'pending-receiver': 'pic.crucible_pit[0].phase = CRUCIBLE_PIC_PIT_CONSUMED;', 'known-high': 'pic.crucible_pit[0].high_known = false;', 'original-generation': 'pic.crucible_pit[0].original.generation++;', 'original-run': 'vm.target.crucible_timer_run_owner = NULL;', 'locked-geometry': 'pic.pics[0].irq_base ^= 8;', 'auto-eoi': 'pic.pics[0].auto_eoi = 1;', 'slave-cascade': 'pic.pics[1].irr = 1;', 'queued-vector': 'change_queued_vector = true;', 'final-pic-disposition': 'close_after_pic_collection = true;', 'controller-write': 'pic_lock(&pic);'}

output = ROOT / 'model'
output.mkdir(exist_ok=True)
commands = []
expected_assertions = {
    'original-pit-source': '!pic.pics[0].irr && !pic.pics[0].last_irr && !native_wakes',
    'pending-receiver': 'architecture_irq_tail(&vm.target) == -EAGAIN',
    'known-high': 'architecture_irq_tail(&vm.target) == -EAGAIN',
    'original-generation': 'pic.pics[0].irr == 1 && !pic.pics[0].isr && !native_queues',
    'original-run': '!pic_pit_consume_begin_locked(&pic, &vm.target, 0)',
    'locked-geometry': 'pic.pics[0].irr == 1 && !pic.pics[0].isr && !native_queues',
    'auto-eoi': 'pic.pics[0].irr == 1 && !generic_notifiers && !native_queues',
    'slave-cascade': 'architecture_irq_tail(&vm.target) == -EAGAIN',
    'queued-vector': 'architecture_irq_tail(&vm.target) == -EAGAIN',
    'controller-write': '!pic_pit_controller_write_safe_locked(&pic)',
    'final-pic-disposition': 'pic.crucible_pit[0].phase == CRUCIBLE_PIC_PIT_UNKNOWN',
}
for name, body, expected in variants:
    path = output / f'{name}.c'
    path.write_text(body)
    assertion = expected_assertions.get(name)
    assertion_line = None
    if assertion is not None:
        anchor = case_anchors[name]
        case_body = function(body, 'static void cases(')
        case_start = body.index(case_body) + case_body.index(anchor)
        assertion_start = body.index('assert(' + assertion + ');', case_start)
        assertion_line = body[:assertion_start].count('\n') + 1
    commands.append({
        'name': name, 'source': measure(path), 'expected_model_returncode': expected,
        'expected_assertion': assertion,
        'expected_assertion_line': assertion_line,
        'argv': [*COMPILER, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
                 str(path), '-o', str(output / name)],
        'output': str(output / name),
    })
proposal = ROOT / 'model-proposal.json'
proposal.write_text(json.dumps(commands, indent=2) + '\n')

# Complete static reference audit is evidence about scaffold construction only.
# It never substitutes a compiler-success or intended-assertion outcome.
audit = []
for row in commands:
    body = Path(row['source']['path']).read_text()
    lexical = re.sub(r'/\*.*?\*/|//[^\n]*', '', body, flags=re.S)
    definitions = re.findall(r'\bstatic(?:\s+inline)?\s+\w+(?:\s+\w+)?\s+(\w+)\s*\(', lexical)
    counts = {name: len(re.findall(r'\b' + name + r'\s*\(', lexical))
              for name in definitions}
    pasted = {name: len(re.findall(r'kvm_x86_call\(' + name.removeprefix('modeled_') +
                                  r'\)', lexical))
              for name in definitions if name.startswith('modeled_')}
    for name, count in pasted.items():
        counts[name] += count
    audit.append({'name': row['name'], 'static_reference_counts': counts,
                  'token_pasted_call_counts': pasted,
                  'only_definition': [name for name, count in counts.items() if count == 1]})
(ROOT / 'scaffold-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
print(measure(proposal))

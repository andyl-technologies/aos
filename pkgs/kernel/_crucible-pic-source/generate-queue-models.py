"""Extracts a bounded original queue/EOI scheduler proposal without execution."""

from pathlib import Path
import hashlib
import json
import re
import shlex
import sys

HERE = Path(__file__).resolve().parent
SOURCE = Path(sys.argv[1]).resolve() / 'arch/x86/kvm'
PARENT = SOURCE
COMPILER = shlex.split(sys.argv[2])


def function(body, signature):
    start = body.rindex(signature)
    opening = body.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (body[end] == '{') - (body[end] == '}')
        end += 1
    return body[start:end]


def once(body, before, after):
    if body.count(before) != 1:
        raise RuntimeError('Nonunique original source control')
    return body.replace(before, after)


def measure(path):
    body = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}


if sys.flags.optimize:
    raise RuntimeError('Optimized source generation refuses')
output = Path(sys.argv[3]).resolve()
output.mkdir()
header = (SOURCE / 'i8254.h').read_text()
start = header.index('struct kvm_crucible_pit_expiry {')
end = header.index('struct kvm_kpit_state {', start)
journals = header[start:end]
phases = '\n'.join(line for line in (PARENT / 'irq.h').read_text().splitlines()
                   if line.startswith('#define CRUCIBLE_PIC_PIT_'))
peers = (HERE / 'queue-peers.c.in').read_text().replace('@JOURNALS@', journals)
peers = peers.replace('@PIC_PHASES@', phases)
ancestry = (SOURCE / 'crucible-pit-ancestry.inc.c').read_text()
native = '\n\n'.join(function(ancestry, signature) for signature in (
    'static bool pit_native_selected(', 'static bool pit_native_live_locked(',
    'static bool pit_native_birth_locked(', 'static bool pit_native_schedule_locked(',
    'bool kvm_crucible_pit_pic_release_locked('))
# Exact worker admission prefix; the IRQ/NMI effect body remains outside this
# model. Remove only declarations unused after that explicit source boundary.
worker = function(ancestry, 'static void pit_native_work(')
worker = worker[:worker.index('\n\twhile (row->phase < 2) {')]
for declaration in ('\tstruct kvm_vcpu *vcpu;\n',
                    '\tstruct kvm_crucible_pit_irq_birth birth;\n',
                    '\tint native_result;\n'):
    worker = once(worker, declaration, '')
worker = once(worker, 'unsigned long flags, index;', 'unsigned long flags;')
worker += '\n}\n'
native += '\n\n' + function(ancestry, 'static void pit_native_fault(') + '\n\n' + worker
finish = function((SOURCE / 'crucible-pic-eoi.inc.c').read_text(),
                  'static int pic_pit_eoi_finish(')
base = '\n\n'.join((peers, native, finish, (HERE / 'queue-cases.c.in').read_text()))
controls = [
    ('worker-known-publication', 'static void pit_native_work(',
     'journal->queue_known &&', 'true &&',
     '!pit.pit_state.crucible.worker_active'),
    ('worker-original-head', 'static void pit_native_work(',
     'journal->queue_head_sequence == journal->pending[journal->head].sequence &&',
     'true &&', '!pit.pit_state.crucible.worker_active'),
    ('original-eoi-deferral', 'static bool pit_native_schedule_locked(',
     'if (pic && pic->crucible_pit[0].eoi_inflight) {', 'if (false) {',
     '!pit_native_schedule_locked(&pit)'),
    ('deferred-head', 'static bool pit_native_schedule_locked(',
     'journal->deferred_head_sequence != next->sequence ||', 'false ||',
     'pic_pit_eoi_finish_placeholder'),
    ('deferred-generation', 'static bool pit_native_schedule_locked(',
     'journal->deferred_generation != next->generation ||', 'false ||',
     'pic_pit_eoi_finish_placeholder'),
    ('finite-publication', 'static bool pit_native_schedule_locked(',
     'journal->queue_issued >= KVM_CRUCIBLE_PIT_ISSUED ||', 'false ||',
     'pic_pit_eoi_finish_placeholder'),
    ('native-queue-result', 'static bool pit_native_schedule_locked(',
     '!queued || !pit_native_live_locked(kvm)', '(!queued && false) || !pit_native_live_locked(kvm)',
     'pic_pit_eoi_finish_placeholder'),
    ('release-live-return', 'bool kvm_crucible_pit_pic_release_locked(',
     'return pit_native_live_locked(kvm);', 'return true;',
     'pic_pit_eoi_finish_placeholder'),
    ('publication-before-release', 'static int pic_pit_eoi_finish(',
     'if (valid && !kvm_crucible_pit_pic_release_locked(kvm, row->eoi_sequence)) {',
     'if (false && !kvm_crucible_pit_pic_release_locked(kvm, row->eoi_sequence)) {',
     'native_queues == 1 && queue_credit_seen == 1'),
]
variants = [('corrected', base, 0, None)]
for name, signature, before, after, assertion in controls:
    original = function(base, signature)
    if name in ('deferred-head', 'deferred-generation'):
        # The first occurrence validates a still-inflight deferred capture.
        # Erase only the final publication check after original exclusivity ends.
        if original.count(before) != 2:
            raise RuntimeError('Changed two original deferred checks')
        position = original.rindex(before)
        changed = original[:position] + after + original[position + len(before):]
    else:
        changed = once(original, before, after)
    if assertion == 'pic_pit_eoi_finish_placeholder':
        assertion = 'original_finish(&lease) == -EAGAIN'
    variants.append((name, once(base, original, changed), -6, assertion))
commands = []
for name, source, status, assertion in variants:
    path = output / (name + '.c')
    path.write_text(source)
    line = None
    if assertion is not None:
        match = 'assert(' + assertion + ');'
        if source.count(match) != 1:
            raise RuntimeError('Nonunique original case assertion')
        line = source[:source.index(match)].count('\n') + 1
    lexical = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
    definitions = re.findall(r'\bstatic(?:\s+inline)?\s+\w+(?:\s+\w+)?\s+(\w+)\s*\(', lexical)
    counts = {name: len(re.findall(r'\b' + name + r'\s*\(', lexical)) for name in definitions}
    commands.append({'name': name, 'source': measure(path), 'expected_returncode': status,
                     'expected_model_returncode': status, 'output': str(output / name),
                     'expected_assertion': assertion, 'expected_assertion_line': line,
                     'static_reference_counts': counts,
                     'argv': [*COMPILER,
                              '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
                              str(path), '-o', str(output / name)]})
(output / 'model-proposal.json').write_text(json.dumps(commands, indent=2) + '\n')
print('Ten source-model proposals only; no compiler or model execution')

"""Reject compiled original-response caller defects without native qualification."""

from pathlib import Path
import subprocess
import sys


MUTATIONS = {
    'changed-original-fragment': (
        'service->exit_sequence == exit_sequence;',
        'true;',
    ),
    'duplicate-submit-after-lost-reply': (
        'CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT && !retry',
        'CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT',
    ),
    'response-byte-geometry-custody': (
        'entry->opaque_effects || !completion_geometry(state, cpu, entry, false)',
        'entry->opaque_effects',
    ),
    'original-attribute-admission': (
        '!service->attributes_known || service->service_id == UINT64_MAX',
        'service->service_id == UINT64_MAX',
    ),
    'other-owner-released-by-cached-poll': (
        'if (!service->collected) {',
        'if (true) {',
    ),
    'unknown-handler-custody': (
        'if (callback_result >= 0) {',
        'if (true) {',
    ),
    'device-failure-consumed-as-success': (
        'if (result >= 0 && !kvm_crucible_userspace_after_dispatch(state, cpu)) {',
        'if (!kvm_crucible_userspace_after_dispatch(state, cpu)) {',
    ),
    'clock-closure-admission': (
        'if (result < 0 || clock.active || clock.run_owners || !clock.close_acknowledged) {',
        'if (result < 0) {',
    ),
}


def main():
    if len(sys.argv) != 7:
        raise SystemExit('usage: mutations.py SOURCE AOS_CC OUTPUT KERNEL MODEL BASELINE_MODEL')
    source, compiler, output, kernel, model, baseline = (
        Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]),
        Path(sys.argv[5]), Path(sys.argv[6]),
    )
    output.mkdir(parents=True, exist_ok=True)
    relative = 'accel/kvm/crucible-clock.c'
    original = (source / relative).read_text()
    for name, (before, after) in MUTATIONS.items():
        # Clock closure also appears in the earlier completion namespace.
        # Mutate only this independently owned original-response component.
        marker = '/* This optional original-response service'
        prefix, response_tail = original.split(marker, 1)
        service, initial = response_tail.split(
            'CrucibleKvmInitialResponseInfo *qmp_x_crucible_kvm_initial_response(', 1,
        )
        if service.count(before) != 1:
            raise ValueError('ambiguous actual source mutation: ' + name)
        changed = (prefix + marker + service.replace(before, after) +
                   'CrucibleKvmInitialResponseInfo *qmp_x_crucible_kvm_initial_response(' + initial)
        case = output / name
        candidate = case / 'source'
        candidate.mkdir(parents=True, exist_ok=True)
        # QAPI and native ABI sources remain actual immutable original files.
        for child in source.iterdir():
            if child.name not in ['accel', 'build']:
                (candidate / child.name).symlink_to(child.resolve())
        (candidate / 'accel/kvm').mkdir(parents=True, exist_ok=True)
        for child in (source / 'accel/kvm').iterdir():
            if child.name != 'crucible-clock.c':
                (candidate / 'accel/kvm' / child.name).symlink_to(child.resolve())
        (candidate / relative).write_text(changed)
        result = subprocess.run(
            [sys.executable, str(model), str(candidate), compiler, str(case / 'proof'),
             str(kernel), str(baseline)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45,
        )
        (case / 'result.log').write_text(result.stdout)
        if (result.returncode == 0 or not (case / 'proof/response').is_file()
                or 'died with <Signals.SIGABRT: 6>' not in result.stdout
                or 'Assertion' not in result.stdout):
            raise AssertionError('compiled source mutation not rejected: ' + name)
        print('Compiled original response defect rejected:', name)
    print(f'All {len(MUTATIONS)} caller custody mutants rejected; no native qualification')


if __name__ == '__main__':
    main()

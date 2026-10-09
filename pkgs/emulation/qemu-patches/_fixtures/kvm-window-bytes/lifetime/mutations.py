"""Require compiled assertions to reject missing or late native lifetime fences."""

from pathlib import Path
import shutil
import subprocess
import sys


source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
output.mkdir(parents=True, exist_ok=True)
original = (source / 'accel/kvm/kvm-all.c').read_text()
guard = '    qemu_cpu_paused_service_reclaim_guard(cpu);\n'
assert original.count(guard) == 1
late = '    ret = kvm_arch_destroy_vcpu(cpu);\n'
begin = original.index('static int do_kvm_destroy_vcpu(')
end = original.index('\n}\n', begin) + 3
assert original[begin:end].count(late) == 1
changes = (
    ('missing-original-reclaim-fence', original.replace(guard, '', 1)),
    ('late-after-architecture-release', original.replace(guard, '', 1).replace(
        late, late + guard, 1)),
)
for name, body in changes:
    candidate = output / name / 'source'
    (candidate / 'accel/kvm').mkdir(parents=True, exist_ok=True)
    (candidate / 'accel/kvm/kvm-all.c').write_text(body)
    shutil.copyfile(source / 'cpu-common.c', candidate / 'cpu-common.c')
    proof = output / name / 'proof'
    result = subprocess.run([
        sys.executable, str(Path(__file__).with_name('model.py')),
        str(candidate), compiler, str(proof),
    ], capture_output=True, timeout=30)
    (output / name / 'stdout').write_bytes(result.stdout)
    (output / name / 'stderr').write_bytes(result.stderr)
    assert (proof / 'lifetime').is_file(), name
    assert result.returncode != 0 and b'Assertion' in result.stderr, name
    assert b'died with <Signals.SIGABRT: 6>' in result.stderr, name
    print(name + ': actual compiled assertion rejects destruction before custody fence')
print('Two native lifetime source mutants PASS; no hardware or installed supervision qualification.')

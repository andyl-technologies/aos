"""Reject compiler-success source mutations of actual stopped CPU custody.

The extracted CPU predicates run with real held pthread callbacks and queues.
Compiler failures and adapter exceptions cannot count as detected defects.
"""
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
root = Path(__file__).parent
source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
output.mkdir(parents=True, exist_ok=True)

cases = [
    ('inflight-ordinary', 'cpu-common.c',
     '        !cpu->crucible_paused_service.ordinary_depth &&', '        true &&'),
    ('uncollected-original', 'cpu-common.c',
     '        !cpu->crucible_paused_service.active &&', '        true &&'),
    ('queued-original', 'cpu-common.c',
     '        QSIMPLEQ_EMPTY(&cpu->work_list);', '        true;'),
    ('native-run-owner', 'cpu-common.c',
     'cpu->stopped && !cpu->crucible_native_window_run &&', 'cpu->stopped && true &&'),
    ('source-window-run', 'system/cpus.c',
     '(!cpu->crucible_native_window_run && !runstate_is_running())',
     '!runstate_is_running()'),
]

for name, relative, before, after in cases:
    candidate = output / name / 'source'
    candidate.mkdir(parents=True, exist_ok=True)
    (candidate / 'include').symlink_to(source / 'include')
    for path in ('cpu-common.c', 'system/cpus.c'):
        target = candidate / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / path, target)

    path = candidate / relative
    body = path.read_text()
    assert body.count(before) == 1, (name, body.count(before))
    path.write_text(body.replace(before, after, 1))
    result = subprocess.run(
        [sys.executable, str(root / 'window-producer.py'), str(candidate),
         compiler, str(output / name / 'proof')],
        capture_output=True, timeout=40,
    )
    (output / name / 'stdout').write_bytes(result.stdout)
    (output / name / 'stderr').write_bytes(result.stderr)
    assert (output / name / 'proof/slot').is_file(), name
    assert result.returncode != 0, name
    assert b'died with <Signals.SIGABRT: 6>' in result.stderr, name
    assert b'Assertion' in result.stderr, name
    print(name + ': actual source compiled; held native assertion rejected defect')

print('Five stopped-owner source mutations rejected; no native KVM qualification.')

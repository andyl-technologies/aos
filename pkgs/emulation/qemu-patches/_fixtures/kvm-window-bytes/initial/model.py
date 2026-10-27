"""Exercise actual first-response source in an explicit native plumbing model.

The real original-owner validator, callback dispatcher, request journal and
kernel completion policy are extracted unchanged. CPU scheduling, original RUN
receipt birth and host QMP serialization are modeled; no hardware/full-node
qualification is represented by these tests.
"""
from pathlib import Path
import importlib.util
import re
import shutil
import subprocess
import sys

root = Path(__file__).parent.parent
source, compiler, output, kernel = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
output.mkdir(parents=True, exist_ok=True)
baseline = Path(__file__).parent / 'completion-model.py'
response = Path(__file__).parent / 'more-model.py'

# Include the genuine new CPU fields without inventing their scheduler proof.
body = baseline.read_text()
assert body.count('    bool created, stopped;') == 1
body = body.replace('    bool created, stopped;', '    bool created, stopped, unplug, crucible_native_window_run;')
body = body.replace('static bool native_enabled =', 'static uint64_t model_clock_generation;\nstatic bool native_enabled =')
old = '    clock->close_acknowledged = clock_ack; return 0;'
assert body.count(old) == 1
body = body.replace(old, '    clock->close_acknowledged = clock_ack;\n    clock->window_generation = model_clock_generation; return 0;')
(output / 'completion-baseline.py').write_text(body)

# Supply exact new QAPI/type source and genuine original-owner functions before
# the existing generator compiles its complete response caller/test program.
body = response.read_text().replace(r'(?:typedef )?struct ', r'(?:typedef )?(?:struct|enum) ')
body = body.replace("result + ' ' + name", "result + r'\\s*' + name")
body = body.replace('    body.write_text(generated +', '    body.write_text(generated +')
marker = "    body.write_text(generated + '\\n' + plumbing + '\\n' + functions + TESTS)"
assert body.count(marker) == 1
insertion = r'''
    window = (source / 'include/system/crucible-kvm-window.h').read_text()
    window_source = (source / 'accel/kvm/crucible-window.c').read_text()
    extras = '\n'.join(line for line in window.splitlines() if line.startswith('#define KVM_') and not line.endswith(chr(92)))
    extras += '\n' + record(window, 'kvm_crucible_run_return')
    extras += '\n' + record(window, 'CrucibleKvmInitialResponseJournal')
    extras += '\n' + record(window, 'CrucibleKvmOriginalReturn')
    extras += '\n' + record(window, 'CrucibleKvmWindowVcpu')
    extras += '\n' + record(qapi, 'CrucibleKvmInitialResponseOperation')
    extras += '\ntypedef struct CrucibleKvmInitialResponseInfo CrucibleKvmInitialResponseInfo;\n' + record(qapi, 'CrucibleKvmInitialResponseInfo')
    extras += '\nstatic bool model_stopped = true;\nstatic bool qemu_cpu_native_window_stopped(CPUState *cpu) { return model_stopped && cpu->stopped && !model_slot.active; }\n'
    extras += '\n' + function(window_source, 'window_vcpu_locked', 'CrucibleKvmWindowVcpu \\*')
    extras += '\n' + function(window_source, 'run_receipt_shape', 'bool')
    extras += '\n' + function(window_source, 'run_receipt_same', 'bool')
    extras += '\n' + function(window_source, 'kvm_crucible_window_initial_record_locked', 'CrucibleKvmOriginalReturn \\*')
    extras += '\n' + function(window_source, 'kvm_crucible_window_initial_response_owner_locked', 'CPUState \\*')
    body.write_text(generated + '\n' + plumbing + '\n' + extras + '\n' + functions + TESTS)
'''
body = body.replace(marker, insertion)
script = output / 'response-adapter.py'
script.write_text(body)
subprocess.run([sys.executable, str(script), str(source), compiler, str(output / 'legacy'), str(kernel), str(output / 'completion-baseline.py')], check=True)

generated = (output / 'legacy/response.c').read_text()
generated = generated.replace('int main(void)', 'int legacy_response_tests(void)')
tests = (Path(__file__).parent / 'initial-cases.inc').read_text()
(output / 'initial-response.c').write_text(generated + '\n' + tests)
executable = output / 'initial-response'
subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-I' + str(source / 'linux-headers'), '-I' + str(output / 'legacy/completion-disabled/include'), str(output / 'initial-response.c'), '-o', str(executable)], check=True)
subprocess.run([str(executable)], check=True, timeout=20)
print('Actual source initial-response and preserved completion/More tests pass; CPU scheduling/RUN receipt birth modeled, no hardware qualification.')

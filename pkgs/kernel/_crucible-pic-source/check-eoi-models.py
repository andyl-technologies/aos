"""Checks exact original EOI source controls and retains first-failure command history.

Native objects and these model outputs share the original aggregate output
reservation. A compiler error, timeout, or unrelated abort never counts as a
successful guard-removal control.
"""

import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys

from resources import check


def identity(path):
    body = path.read_bytes()
    return {'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}


def execute(argv, root, name, phase, deadline, row):
    stdout = root / (name + '.' + phase + '.stdout')
    stderr = root / (name + '.' + phase + '.stderr')
    command = {'argv': argv, 'deadline_seconds': deadline, 'returncode': None,
               'timed_out': False, 'stdout': str(stdout), 'stderr': str(stderr)}
    row[phase] = command
    with stdout.open('wb') as out, stderr.open('wb') as err:
        try:
            result = subprocess.run(argv, stdout=out, stderr=err, timeout=deadline)
        except subprocess.TimeoutExpired:
            command['timed_out'] = True
            raise
        else:
            command['returncode'] = result.returncode
            return result.returncode
        finally:
            command['stdout_identity'] = identity(stdout)
            command['stderr_identity'] = identity(stderr)


def main():
    if sys.flags.optimize:
        raise RuntimeError('Optimized evidence execution refuses')
    root = Path(sys.argv[1]).resolve()
    budget = Path(sys.argv[2]).resolve()
    rows = json.loads((root / 'model-proposal.json').read_text())
    if len(rows) != 17:
        raise ValueError('Closed seventeen-control roster changed')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    report = {'source_models': [], 'completed': False, 'failure': None,
              'hardware_qualification': False,
              'PIC_EOI_dual_route_FirstBegin_board_Ready_capture': 'Unsupported'}

    try:
        for original in rows:
            source = Path(original['source']['path'])
            if identity(source) != {key: original['source'][key]
                                    for key in ['sha256', 'bytes']}:
                raise ValueError('Changed generated original control')
            row = {'name': original['name'], 'source': identity(source),
                   'expected_model_returncode': original['expected_model_returncode'],
                   'expected_assertion': original['expected_assertion'],
                   'expected_assertion_line': original['expected_assertion_line'],
                   'passed': False}
            report['source_models'].append(row)
            row['before_compile'] = check(budget)
            if execute(original['argv'], root, row['name'], 'compiler', 300, row):
                raise RuntimeError('First compiler failure: ' + row['name'])
            row['before_model'] = check(budget)
            status = execute([original['output']], root, row['name'], 'model', 30, row)
            if status != original['expected_model_returncode']:
                raise RuntimeError('First original control failure: ' + row['name'])
            expected = original['expected_assertion']
            if expected is not None:
                location = str(source) + ':' + str(original['expected_assertion_line']) + ':'
                stderr = Path(row['model']['stderr']).read_bytes()
                if (location.encode() not in stderr or b'Assertion' not in stderr or
                        expected.encode() not in stderr):
                    raise RuntimeError('Unrelated assertion abort: ' + row['name'])
            row['after_model'] = check(budget)
            row['passed'] = True
            print(row['name'] + ': original source control passed', flush=True)
        report['completed'] = True
    except BaseException as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

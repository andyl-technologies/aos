# SPDX-License-Identifier: Apache-2.0
"""Measure identical finite ROM work across distinct TCG clock contracts.

The same ROM bytes and iteration count execute in every row. Spawn-to-END and
START-to-END socket receipt intervals are reported for ordinary controls.
Managed Sim reports the authenticated stop and makes no socket receipt ROI claim. UART polling,
checksum formatting and transport latency are included in the latter interval;
only the seven-instruction arithmetic loop has a static retired-work count.
Sim's secondary authenticated stop is exact. Stock stops after END and its
optional replay count is not the exact END instruction coordinate.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_witness(sample, manifest):
    if sample['mode'] == 'sim':
        oracle = load_module(Path(__file__).with_name('tcg-managed-performance-oracle.py'),
                             'managed_performance_oracle')
        oracle.require_witness(sample, 'rom', 64)
        if sample['manifest'] != manifest:
            raise AssertionError('managed finite manifest differs from independent arithmetic input')
        return
    if sample['manifest'] != manifest or sample['record_hex'] != manifest['record_hex']:
        raise AssertionError('finite work manifest/checksum/counter/tag mismatch')
    if sample['captured_ram_bytes'] != 64 * 1024 * 1024 or sample['status']['status'] != 'paused':
        raise AssertionError('incomplete or running stopped capture')
    valid_roi = 0 < sample['roi_seconds'] <= sample['seconds']
    valid_startup = 0 <= sample['startup_seconds'] <= sample['seconds']
    if not valid_roi or not valid_startup:
        raise AssertionError('invalid serial endpoint ordering')
    registers = sample['registers']
    register_fields = re.findall(r'\b(EAX|ECX|ESP|EIP|EFL|HLT)=([0-9a-fA-F]+)', registers)
    values = {name: int(value, 16) for name, value in register_fields}
    expected_tail = {
        'EAX': manifest['checksum'],
        'ECX': 0,
        'ESP': 0x6000,
        'EIP': manifest['halted_address'] + 2,
        'HLT': 1,
    }
    if any(values[name] != expected for name, expected in expected_tail.items()):
        raise AssertionError('restored permanent halt register witness mismatch')
    if values['EFL'] & 0x200:
        raise AssertionError('permanent halt unexpectedly permits interrupts')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--row', nargs=4, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--host-cpu', type=int, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--continue-failed', action='store_true')
    args = parser.parse_args()
    profiling = os.environ.get('LD_PRELOAD') or os.environ.get('CPUPROFILE')
    if args.output.exists() or args.rounds < 1 or profiling:
        raise ValueError('use new output, positive rounds and no profiling preload')
    here = Path(__file__).parent
    support = load_module(here / 'tcg-linux-boot-performance.py', 'support')
    arithmetic = load_module(here / 'tcg-finite-rom-test.py', 'arithmetic')
    manifest_path = (args.fixtures / 'manifest.json').resolve(strict=True)
    manifest = json.loads(manifest_path.read_text())
    # Recompute independently before any timing, rather than trust a checksum
    # copied from the guest or from a previous emulator version.
    if arithmetic.reference_checksum(manifest['iterations']) != manifest['checksum']:
        raise AssertionError('fixture checksum disagrees with independent arithmetic oracle')
    rom = (args.fixtures / 'rom.bin').resolve(strict=True)
    driver = args.driver.resolve(strict=True)
    rows = {}
    for label, mode, qemu, plugin in args.row:
        if label in rows or not re.fullmatch(r'[A-Za-z0-9_-]+', label):
            raise ValueError('unique path-safe labels required')
        if mode not in ('tcg', 'tcg-icount', 'sim') or (plugin == '-') != (mode != 'sim'):
            raise ValueError('Sim requires plugin, ordinary TCG takes dash')
        binary = Path(qemu).resolve(strict=True)
        plugin_path = None if plugin == '-' else Path(plugin).resolve(strict=True)
        identity = binary.parent.parent / 'share/aos/crucible/qemu-build-identity.env'
        rows[label] = {
            'mode': mode,
            'qemu': str(binary),
            'qemu_sha256': support.sha256(binary),
            'plugin': str(plugin_path) if plugin_path else None,
            'plugin_sha256': support.sha256(plugin_path) if plugin_path else None,
            'qemu_build_identity': identity.read_text() if identity.exists() else None,
        }

    os.sched_setaffinity(0, {args.host_cpu})
    args.output.mkdir(parents=True)
    result = {
        'scope': __doc__,
        'rows': rows,
        'rounds': args.rounds,
        'platform': support.platform_metadata({args.cpu, args.host_cpu}),
        'driver_sha256': support.sha256(driver),
        'runner_sha256': support.sha256(Path(__file__)),
        'rom_sha256': support.sha256(rom),
        'manifest': manifest,
        'attempts': [],
        'samples': [],
        'campaign_complete': False,
    }
    expected_sim = None

    def save():
        result['distributions'] = {}
        for label in rows:
            samples = [sample for sample in result['samples'] if sample['label'] == label]
            result['distributions'][label] = {
                'attempts': sum(attempt['label'] == label for attempt in result['attempts']),
                'passed': len(samples),
                'successful_times_are_conditional': True,
                'seconds': support.distribution([sample['seconds'] for sample in samples]) if samples else None,
                'roi_seconds': support.distribution([sample['roi_seconds'] for sample in samples]) if samples else None,
            }
        (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')

    save()
    for round_index in range(args.rounds):
        for position, label in enumerate(support.trial_order(list(rows), round_index)):
            row = rows[label]
            directory = args.output / f'round-{round_index}-{position}-{label}'
            directory.mkdir()
            command = [
                str(driver), row['mode'], row['qemu'], row['plugin'] or '-',
                str(rom), str(directory), str(args.cpu), str(manifest_path),
            ]
            attempt = {
                'label': label,
                'round': round_index,
                'position': position,
                'command': command,
                'outcome': 'started',
            }
            result['attempts'].append(attempt)
            save()
            trial_environment = dict(os.environ)
            trial_environment["CRUCIBLE_TCG_TRIAL_INDEX"] = str(round_index * len(labels) + position)
            completed = subprocess.run(command, text=True, capture_output=True, check=False,
                                       env=trial_environment)
            (directory / 'stdout.log').write_text(completed.stdout)
            (directory / 'stderr.log').write_text(completed.stderr)
            attempt['exit_status'] = completed.returncode
            if completed.returncode:
                timeout = 'ROM completion timeout after 300 seconds' in completed.stderr
                early_exit = 'QEMU exited before ROM completion' in completed.stderr
                recognized = timeout or early_exit
                attempt['outcome'] = 'failed' if recognized else 'invalid_or_infrastructure_error'
                if timeout:
                    attempt['censored_timeout_seconds'] = 300
                save()
                if recognized and args.continue_failed:
                    continue
                raise RuntimeError('finite ROM trial failed without retry; retained stderr')
            try:
                sample = json.loads(completed.stdout)
                (directory / 'result.json').write_text(json.dumps(sample, indent=2) + '\n')
                expected = {
                    'mode': row['mode'],
                    'qemu': row['qemu'],
                    'plugin': row['plugin'],
                    'rom': str(rom),
                    'cpu': args.cpu,
                }
                if any(sample[key] != value for key, value in expected.items()):
                    raise AssertionError('successful sample artifact identity mismatch')
                require_witness(sample, manifest)
                if row['mode'] == 'sim':
                    oracle = load_module(here / 'tcg-managed-performance-oracle.py',
                                         'managed_performance_oracle')
                    witness_keys = oracle.WITNESS_KEYS
                    witness = {key: sample[key] for key in witness_keys}
                    if expected_sim is None:
                        expected_sim = witness
                    elif witness != expected_sim:
                        raise AssertionError('same-work Sim deterministic witness changed')
            except (AssertionError, KeyError, ValueError) as error:
                attempt.update(outcome='invalid_witness', error=str(error))
                save()
                raise
            sample.update(label=label, round=round_index, position=position)
            result['samples'].append(sample)
            attempt['outcome'] = 'passed'
            save()
            progress = {
                'label': label,
                'round': round_index,
                'seconds': sample['seconds'],
                'roi_seconds': sample.get('roi_seconds'),
                'measurement_scope': sample.get('measurement_scope', 'serial socket receipt'),
            }
            print(json.dumps(progress), flush=True)
    result['campaign_complete'] = True
    result['sim_witness'] = expected_sim
    save()


if __name__ == '__main__':
    main()

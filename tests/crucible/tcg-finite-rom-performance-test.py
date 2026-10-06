# SPDX-License-Identifier: Apache-2.0
"""Mutation controls for the actual finite-work runner admission oracle."""

import copy
import importlib.util
from pathlib import Path
import struct
import unittest


runner_path = Path(__file__).with_name('tcg-finite-rom-performance.py')
spec = importlib.util.spec_from_file_location('runner', runner_path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            'iterations': 17,
            'checksum': 12345,
            'record_hex': struct.pack('<IIII', 12345, 0, 17, 0x524F4D31).hex(),
            'loop_retired_instructions': 119,
            'request_address': 0xF0400,
            'halted_address': 0xF0100,
        }
        self.sample = {
            'manifest': self.manifest,
            'record_hex': self.manifest['record_hex'],
            'captured_ram_bytes': 64 * 1024 * 1024,
            'status': {'status': 'paused'},
            'seconds': 2.0,
            'roi_seconds': 1.0,
            'startup_seconds': 0.1,
            'registers': 'EAX=000f0400 ECX=00000080 ESP=00005ff8',
            'mode': 'sim',
            'sim_saved_registers_hex': struct.pack('<II', 0, 12345).hex(),
            'raw_icount': 200,
            'logical_tick': 10000,
            'idle_wake_tick': 10000,
            'markers': [{'kind': 4}],
            'request': {
                'sequence': 2,
                'raw_icount': 199,
                'logical_tick': 9950,
                'selectable_id': 'flight.ready',
                'instance_key': 'boot',
            },
        }

    def test_valid_sim_and_stock_records(self):
        runner.require_witness(self.sample, self.manifest)

        stock = copy.deepcopy(self.sample)
        stock.update(
            mode='tcg',
            registers='EAX=00003039 ECX=00000000 ESP=00006000 EIP=000f0102 EFL=00000002 HLT=1',
        )
        runner.require_witness(stock, self.manifest)

    def test_saved_counter_checksum_and_native_operand_mutations(self):
        mutations = [
            ('record_hex', '00' * 16),
            ('sim_saved_registers_hex', '01' * 8),
            ('registers', 'EAX=000f0401 ECX=00000080 ESP=00005ff8'),
            ('logical_tick', 10050),
            ('idle_wake_tick', 10050),
            ('captured_ram_bytes', 65536),
            ('markers', []),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.sample)
                mutated[field] = value

                with self.assertRaises(AssertionError):
                    runner.require_witness(mutated, self.manifest)

    def test_stock_final_register_mutation(self):
        stock = copy.deepcopy(self.sample)
        stock.update(
            mode='tcg',
            registers='EAX=00003038 ECX=00000000 ESP=00006000 EIP=000f0102 EFL=00000002 HLT=1',
        )

        with self.assertRaises(AssertionError):
            runner.require_witness(stock, self.manifest)

    def test_early_epilogue_is_not_a_qualified_stock_halt(self):
        early = copy.deepcopy(self.sample)
        early.update(
            mode='tcg',
            registers='EAX=00003039 ECX=00000000 ESP=00006000 EIP=000f00f0 EFL=00000002 HLT=0',
        )

        with self.assertRaises(AssertionError):
            runner.require_witness(early, self.manifest)


if __name__ == '__main__':
    unittest.main()

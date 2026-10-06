# SPDX-License-Identifier: Apache-2.0
"""Independent finite-work arithmetic oracle and assembled instruction checks."""

import argparse
import json
from pathlib import Path
import struct
import subprocess
import unittest


EXPECTED_LOOP_BYTES = bytes.fromhex(
    'c1c00d35b979379e05f5792b6da30070000049890d0470000075e5'
)


def require_loop_bytes(loop):
    if loop != EXPECTED_LOOP_BYTES:
        raise AssertionError(f'finite loop instruction bytes changed: {loop.hex()}')


def reference_checksum(iterations):
    value = 0x51F15EED
    for _ in range(iterations):
        value = ((value << 13) | (value >> 19)) & 0xFFFFFFFF
        value ^= 0x9E3779B9
        value = (value + 0x6D2B79F5) & 0xFFFFFFFF
    return value


def require_record(record, iterations, checksum):
    expected = (checksum, 0, iterations, 0x524F4D31)
    if struct.unpack('<IIII', record) != expected:
        raise AssertionError('finite-work checksum/counter/tag mismatch')


class OracleTests(unittest.TestCase):
    def test_zero_and_first_step(self):
        self.assertEqual(reference_checksum(0), 0x51F15EED)
        rotated = ((0x51F15EED << 13) | (0x51F15EED >> 19)) & 0xFFFFFFFF
        self.assertEqual(reference_checksum(1), ((rotated ^ 0x9E3779B9) + 0x6D2B79F5) & 0xFFFFFFFF)

    def test_each_witness_mutation_is_rejected(self):
        values = [reference_checksum(17), 0, 17, 0x524F4D31]
        require_record(struct.pack('<IIII', *values), 17, values[0])
        for index in range(4):
            mutated = list(values)
            mutated[index] ^= 1
            with self.assertRaises(AssertionError):
                require_record(struct.pack('<IIII', *mutated), 17, values[0])

    def test_instruction_counter_and_recurrence_mutations_are_rejected(self):
        require_loop_bytes(EXPECTED_LOOP_BYTES)
        for offset in (2, 4, 9, 18, 26):
            mutated = bytearray(EXPECTED_LOOP_BYTES)
            mutated[offset] ^= 1

            with self.assertRaises(AssertionError):
                require_loop_bytes(bytes(mutated))


def build_manifest(args):
    symbols = subprocess.check_output([args.nm, '-n', args.elf], text=True)
    addresses = {
        line.split()[2]: int(line.split()[0], 16)
        for line in symbols.splitlines()
        if len(line.split()) == 3
    }
    binary = Path(args.rom).read_bytes()
    start, end = addresses['workload'], addresses['workload_end']
    loop = binary[start - 0xF0000:end - 0xF0000]
    # Seven actual instructions: rol/xor/add/store/dec/store/jnz. This is a
    # byte-level check independent of disassembler presentation conventions.
    require_loop_bytes(loop)
    counter = binary[start - 0xF0000 - 5:start - 0xF0000]
    if counter != b'\xb9' + struct.pack('<I', args.iterations):
        raise AssertionError('assembled iteration counter disagrees with manifest')
    if len(binary) != 65536 or binary[0xFFF0:0xFFF5] != bytes.fromhex('ea000000f0'):
        raise AssertionError('ROM reset vector/size mismatch')
    if binary[:8] != bytes.fromhex('fa8cc88ed80f0116'):
        raise AssertionError('16-bit CLI/segment/GDT bootstrap changed')
    transition = bytes.fromhex('0f20c06683c8010f22c066ea')
    if binary[10:22] != transition:
        raise AssertionError('CR0 protected-mode transition changed')
    checksum = reference_checksum(args.iterations)
    manifest = {
        'iterations': args.iterations,
        'checksum': checksum,
        'remaining_counter': 0,
        'record_address': 0x7000,
        'record_hex': struct.pack('<IIII', checksum, 0, args.iterations, 0x524F4D31).hex(),
        'start_token': '\nCRUCIBLE_ROM_START_V1\n',
        'end_token': f'\nCRUCIBLE_ROM_DONE_V1:{checksum:08X}:{args.iterations:08X}\n',
        'loop_instruction_count': 7,
        'loop_retired_instructions': 7 * args.iterations,
        'loop_machine_bytes': loop.hex(),
        'loop_start': start,
        'loop_end': end,
        'request_address': addresses['request'],
        'halted_address': addresses['halted'],
        'scope': 'Fixed work, independent of virtual clock; bootstrap and UART/protocol epilogues are outside static loop count',
        'uart_poll_budget_per_byte': 1 << 20,
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf')
    parser.add_argument('--rom')
    parser.add_argument('--nm')
    parser.add_argument('--manifest')
    parser.add_argument('--iterations', type=int)
    args, rest = parser.parse_known_args()
    if args.elf:
        build_manifest(args)
    else:
        unittest.main(argv=['finite-rom-test', *rest])

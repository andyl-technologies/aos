# SPDX-License-Identifier: MIT
"""Refuses changed 9p capture-policy data without constructing a native audit.

The temporary byte fixtures test source role validation only. They are not
process images, live native authority or full-system qualification evidence.
"""

import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


specification = importlib.util.spec_from_file_location(
    'closed_ninep_capture_policy', Path(__file__).with_name('closed-ninep-process-image-audit.py'))
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.owned = Path(self.temporary.name).resolve()
        self.owned.chmod(0o700)
        self.resources = self.owned / 'resources'
        self.resources.mkdir(mode=0o700)
        configs = self.resources / 'configs'
        configs.mkdir(mode=0o700)
        config = configs / 'model.py'
        config.write_bytes(b'fixed-source-model\n')
        config.chmod(0o600)
        roles = {}
        assets = []
        for role, name in (('kernel', 'kernel.elf'), ('initramfs', 'initrd.img'),
                           ('firmware', 'boot_v2.arm64')):
            path = self.resources / name
            path.write_bytes(('data-only-' + role).encode())
            path.chmod(0o600)
            measured = module.asset_custody.digest_file(path, 1024)
            roles[role] = measured
            assets.append({'path': str(path), 'sha256': measured['sha256']})
        scope = {
            'schema': 'crucible.gem5.model-scope.v1',
            'model_id': 'arm-linux-vexpress-atomic-closed-ninep-functional-v1',
            'full_system': True, 'complete_process_closure_qualified': False,
            'cpu_timing_qualified': False, 'guest_readiness_qualified': False,
            'device_parity_qualified': False, 'closed_terminal_monitor': True,
            'external_serial_route': False, 'native_device_execution_parent': '17',
            'native_terminal_parent': '0',
            'device_slots': ['ninep:0x1c130000', 'block:0x1c140000'],
            'diagnostic_scope': 'native-event-device-terminal-and-closed-ninep-block-metadata-v1',
            'diagnostic_maximum_object_bytes': '4194304',
            'maximum_terminal_rows': '32768', 'maximum_native_callbacks': '16000000',
            'maximum_native_tick': '1000000000000',
            'closed_block_backend': {
                'schema': 'crucible.gem5.closed-block-backend-policy.v1',
                'backing_bytes': '1048576', 'initial_bytes': 'zero',
                'maximum_original_commands': '128', 'maximum_payload_bytes': '4096',
                'reaction_delay_ps': '10000', 'completion_delay_ps': '1',
                'execution_parent': '17', 'backend_parent': '23',
                'diagnostic_maximum_bytes': '65536', 'external_inputs_admitted': False,
            },
            'closed_ninep_backend': {
                'schema': 'crucible.gem5.closed-ninep-backend-policy.v1',
                'mount_tag': 'crucible', 'protocol': '9P2000.L',
                'maximum_original_commands': '128', 'maximum_message_bytes': '4096',
                'maximum_file_bytes': '65536', 'maximum_fids': '64',
                'reaction_delay_ps': '10000', 'completion_delay_ps': '1',
                'execution_parent': '17', 'backend_parent': '23',
                'diagnostic_maximum_bytes': '65536', 'external_inputs_admitted': False,
            },
            'guest_assets': roles,
            'configuration_tree': module.asset_custody.configuration_tree(configs),
        }
        self.request = {'owned_root': str(self.owned), 'modeled_root': str(self.resources),
                        'model_scope': scope, 'assets': assets}

    def test_source_policy_accepts_only_its_data_roles(self):
        selected = module.ArmFunctionalAssetPolicy(self.request)
        self.assertEqual(selected.paths, {str(self.resources / name)
                                         for name in ('kernel.elf', 'initrd.img', 'boot_v2.arm64')})

    def test_old_model_or_network_slots_are_refused(self):
        for field, value in (('model_id', 'arm-linux-vexpress-atomic-closed-network-functional-v1'),
                             ('device_slots', ['net:0x1c130000', 'block:0x1c140000'])):
            changed = copy.deepcopy(self.request)
            changed['model_scope'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.ArmFunctionalAssetPolicy(changed)

    def test_inflated_closure_or_admission_flags_are_refused(self):
        for field in ('complete_process_closure_qualified', 'cpu_timing_qualified',
                      'guest_readiness_qualified', 'device_parity_qualified', 'external_serial_route'):
            changed = copy.deepcopy(self.request)
            changed['model_scope'][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.ArmFunctionalAssetPolicy(changed)

    def test_unknown_message_file_or_fid_caps_are_refused(self):
        for field, value in (('maximum_message_bytes', '65536'), ('maximum_file_bytes', '131072'),
                             ('maximum_fids', '65'), ('mount_tag', 'external')):
            changed = copy.deepcopy(self.request)
            changed['model_scope']['closed_ninep_backend'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.ArmFunctionalAssetPolicy(changed)

    def test_external_server_inputs_are_refused(self):
        changed = copy.deepcopy(self.request)
        changed['model_scope']['closed_ninep_backend']['external_inputs_admitted'] = True
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(changed)

    def test_unknown_callback_or_diagnostic_caps_are_refused(self):
        for field, value in (('maximum_native_callbacks', '16000001'),
                             ('diagnostic_maximum_object_bytes', '8388608')):
            changed = copy.deepcopy(self.request)
            changed['model_scope'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.ArmFunctionalAssetPolicy(changed)

    def test_missing_asset_role_is_refused(self):
        changed = copy.deepcopy(self.request)
        del changed['model_scope']['guest_assets']['firmware']
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(changed)

    def test_duplicate_asset_path_is_refused(self):
        changed = copy.deepcopy(self.request)
        changed['assets'].append(copy.deepcopy(changed['assets'][0]))
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(changed)

    def test_asset_must_stay_private_single_link_and_source_sized(self):
        leaf = self.resources / 'kernel.elf'
        leaf.chmod(0o640)
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(self.request)
        leaf.chmod(0o600)
        os.link(leaf, self.resources / 'kernel-alias')
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(self.request)

    def test_unknown_asset_binding_hash_is_refused(self):
        changed = copy.deepcopy(self.request)
        changed['assets'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(changed)

    def test_changed_configuration_bytes_are_refused(self):
        (self.resources / 'configs' / 'model.py').write_bytes(b'changed-source-model\n')
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(self.request)

    def test_nonprivate_model_root_is_refused(self):
        self.resources.chmod(0o750)
        with self.assertRaises(ValueError):
            module.ArmFunctionalAssetPolicy(self.request)


if __name__ == '__main__':
    unittest.main()

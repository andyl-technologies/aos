"""Offline launcher contracts using recorded provider CLIs and real Nix evaluation."""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve().with_name("aos-cloud-vm.sh")

FAKE = r'''
import json, os, pathlib, re, sys
root = pathlib.Path(os.environ['CLOUD_FIXTURE'])
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
with (root / 'calls').open('a') as log:
    log.write(json.dumps([name] + args) + '\n')
def value(flag): return args[args.index(flag) + 1]
def read(name): return json.loads((root / name).read_text())
def write(name, data): (root / name).write_text(json.dumps(data))
def once(name):
    path = root / name
    if path.exists(): path.unlink(); return True
    return False
def missing(kind):
    print(kind, file=sys.stderr); sys.exit(1)
if name == 'aos':
    if 'show' in args:
        print((root / 'selection.json').read_text())
    elif 'download' in args:
        source = 'info.json' if '--metadata-only' in args else 'disk'
        pathlib.Path(value('--output')).write_bytes((root / source).read_bytes())
        print(value('--output'))
    else: sys.exit('unexpected aos command')
elif name == 'gcloud':
    if 'projects' in args:
        print(value('--project'))
    elif 'subnets' in args:
        print(json.dumps({'network':'projects/example/global/networks/test-network'}))
    elif 'images' in args:
        if 'create' in args:
            if once('fail-image-create'): sys.exit(1)
            (root / 'image-description').write_text(value('--description'))
            (root / 'image-name').write_text(args[args.index('create') + 1])
        elif 'describe' in args:
            status = 'PENDING' if once('image-pending') else 'READY'
            if (root / 'image-failed').exists(): status = 'FAILED'
            print(json.dumps({'description':(root / 'image-description').read_text(), 'status':status}))
        elif 'list' in args:
            print(json.dumps([] if not (root / 'image-description').exists() or (root / 'image-name').read_text() != value('--filter').removeprefix('name=') else [{'description':(root / 'image-description').read_text()}]))
    elif 'objects' in args and 'describe' in args:
        if not (root / 'image-object-hash').exists(): sys.exit(1)
        print(json.dumps({'metadata':{'aos-prepared-sha256':(root / 'image-object-hash').read_text()}}))
    elif 'storage' in args and 'cp' in args and '--custom-metadata' in args:
        (root / 'image-object-hash').write_text(value('--custom-metadata').split('=',1)[1])
    elif 'instances' in args and 'create' in args:
        if once('fail-instance-create'): sys.exit(1)
        once('spot-deleted')
        instance = dict(id='123456', description=value('--description'), scheduling=dict(provisioningModel=value('--provisioning-model')))
        if '--termination-time' in args:
            instance['scheduling'].update(terminationTime=value('--termination-time'), instanceTerminationAction=value('--instance-termination-action'))
        write('gcp-instance.json', instance)
        if once('lose-instance-response'): sys.exit(1)
        print(json.dumps([instance]))
    elif 'instances' in args and 'list' in args:
        present = (root / 'gcp-instance.json').exists() and not (root / 'spot-deleted').exists()
        print(json.dumps([read('gcp-instance.json')] if present else []))
    elif 'instances' in args and 'delete' in args:
        (root / 'spot-deleted').touch()
    elif 'instances' in args and 'describe' in args:
        print(json.dumps({'networkInterfaces':[{'networkIP':'192.0.2.4','accessConfigs':[{'natIP':'192.0.2.5'}]}]}))
    elif 'sign-url' in args:
        print(json.dumps([{'signed_url':'https://storage.example/config?temporary=' + str(len((root/'calls').read_text()))}]))
elif name == 'aws':
    if 'get-caller-identity' in args: print('123456789012')
    elif 'get-role' in args:
        print(json.dumps({'Role':{'Arn':'arn:aws:iam::123456789012:role/lifetime', 'AssumeRolePolicyDocument':{'Statement':[{'Effect':'Allow','Principal':{'Service':'scheduler.amazonaws.com'}}]}}}))
    elif 'scheduler' in args:
        if 'get-schedule-group' in args: print('{}')
        elif 'get-schedule' in args:
            if not (root / 'schedule.json').exists(): missing('ResourceNotFoundException')
            print((root / 'schedule.json').read_text())
        elif 'create-schedule' in args:
            if (root / 'fail-schedule').exists(): sys.exit(1)
            target = json.loads(pathlib.Path(value('--target')[7:]).read_text())
            write('schedule.json', dict(Description=value('--description'), ScheduleExpression=value('--schedule-expression'),
                ScheduleExpressionTimezone=value('--schedule-expression-timezone'), FlexibleTimeWindow=json.loads(value('--flexible-time-window')),
                ActionAfterCompletion=value('--action-after-completion'), State='ENABLED', Target=target))
            if once('lose-schedule-response'): sys.exit(1)
            print('{}')
        elif 'delete-schedule' in args:
            (root / 'schedule.json').unlink()
    elif 'import-snapshot' in args: print('import-snap-test')
    elif 'describe-import-snapshot-tasks' in args:
        print(json.dumps({'ImportSnapshotTasks':[{'SnapshotTaskDetail':{'Status':'completed','SnapshotId':'snap-test'}}]}))
    elif 'register-image' in args:
        (root / 'aws-image-description').write_text(value('--description')); print('ami-test')
    elif 'describe-images' in args:
        if '--filters' in args: print(json.dumps({'Images':[]}))
        else: print((root / 'aws-image-description').read_text())
    elif 'describe-subnets' in args:
        print(json.dumps({'Subnets':[{'VpcId':'test-network','AvailabilityZone':'test-region-a'}]}))
    elif 'create-security-group' in args: print('sg-test')
    elif 'run-instances' in args:
        if once('fail-instance-create'): sys.exit(1)
        owner = re.search(r'Value=([^}]+)', value('--tag-specifications'))[1]
        instance = dict(InstanceId='i-test', ClientToken=value('--client-token'), Tags=[{'Key':'aos-cloud-vm','Value':owner}], State={'Name':'running'}, PublicIpAddress='192.0.2.5')
        write('aws-instance.json', instance)
        if once('lose-instance-response'): sys.exit(1)
        print('i-test')
    elif 'describe-instances' in args:
        if '--instance-ids' in args and (root / 'aws-instance-missing').exists(): missing('InvalidInstanceID.NotFound')
        exists = (root / 'aws-instance.json').exists()
        if '--filters' in args and (root / 'miss-token-filter').exists(): exists = False
        print(json.dumps({'Reservations':[{'Instances':[read('aws-instance.json')]}] if exists else []}))
    elif 'terminate-instances' in args:
        if (root / 'fail-terminate').exists(): sys.exit(1)
        instance = read('aws-instance.json'); instance['State']['Name'] = 'terminated'; write('aws-instance.json', instance)
    elif 'presign' in args: print('https://storage.example/config?temporary=' + str(len((root/'calls').read_text())))
    elif 'describe-security-groups' in args: print('test-network')
elif name not in ('zstd', 'sgdisk', 'truncate', 'sleep'):
    sys.exit('unexpected tool ' + name)
'''


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.key = self.root / "key.pub"
        self.key.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV4YW1wbGVCb3VuZGVkUHVibGljS2V5Rm9yVGVzdHM= test\n")
        disk = b"synthetic raw disk fixture"
        (self.root / "disk").write_bytes(disk)
        sha = hashlib.sha256(disk).hexdigest()
        (self.root / "selection.json").write_text(json.dumps(dict(release="1.0.0", sha256=sha, compression="none")))
        self.info = dict(
            schema_version="aos.image.metadata/v2",
            disk=dict(logical=dict(sha256=sha, size_bytes=len(disk))),
            capabilities=dict(
                kernel_options={"CONFIG_EFI": "y"},
                builtin_drivers=["virtio_pci", "virtio_scsi", "virtio_net", "nvme", "ena"],
                stages={}, configuration=["aos.config-bundle/v1"],
            ),
        )
        self.write_info()
        for tool in ["aos", "gcloud", "aws", "zstd", "sgdisk", "truncate", "sleep"]:
            path = self.bin / tool
            path.write_text("#!" + sys.executable + "\n" + FAKE)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"], CLOUD_FIXTURE=str(self.root))

    def write_info(self):
        (self.root / "info.json").write_text(json.dumps(self.info))

    def run_launcher(self, command="plan", extra=(), provider="gcp", success=True, state=None):
        args = ["bash", str(SCRIPT), command, "--provider", provider, "--name", "test-vm", "--state-dir", str(state or self.state)]
        if command != "delete":
            args += ["--hub", "https://hub.example", "--registry", "example", "--package", "server", "--release", "1.0.0",
                     "--region", "test-region", "--zone", "test-region-a", "--network", "test-network", "--subnet", "test-subnet",
                     "--bucket", "example-bucket", "--machine-type", "e2-standard-2" if provider == "gcp" else "m6i.large",
                     "--ssh-key", str(self.key), "--ssh-cidr", "192.0.2.0/24", "--disk-size", "8"]
            args += ["--project", "example-project"] if provider == "gcp" else ["--account", "123456789012", "--import-role", "vmimport", "--scheduler-role", "arn:aws:iam::123456789012:role/lifetime"]
        result = subprocess.run(args + list(extra), env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def calls(self):
        path = self.root / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def evaluate(self, module, admitted_root=None, expression_result="{ inherit (evaluated.config) value number; }"):
        expression = f'''let
          lib = import {ROOT / 'lib'} {{ system = builtins.currentSystem; }};
          evaluated = lib.evalModules {{ inherit lib;
            modules = [ {{ options = {{
              value = lib.mkOption {{ type = lib.types.str; default = "package"; }};
              number = lib.mkOption {{ type = lib.types.int; default = 0; }};
              environment.etc = lib.mkOption {{ type = lib.types.attrsOf (lib.types.submodule {{ options.text = lib.mkOption {{ type = lib.types.lines; default = ""; }}; }}); default = {{}}; }};
              aos.services.ssh = lib.mkOption {{ type = lib.types.attrs; default = {{}}; }};
            }}; }} ];
            operatorModules = [ (import {module}) ];
          }};
        in {expression_result}'''
        arguments = ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression]
        if admitted_root is not None:
            arguments += ["--option", "restrict-eval", "true", "--option", "allow-import-from-derivation", "false", "-I", str(admitted_root), "-I", str(ROOT / "lib")]
        result = subprocess.run(arguments, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_plan_has_no_provider_calls_and_preserves_template_words(self):
        config = self.root / "host.nix"
        config.write_text('{ lib, ... }: { value = "FIRST ADDITIONAL ASSIGNMENTS KEY BANNER"; number = lib.mkDefault 1; }')
        plan = self.run_launcher(extra=["--config", str(config), "--set", "number=2"])
        self.assertEqual(json.loads(plan.stdout)["capacity"], "spot")
        value = self.evaluate(self.state / "config-payload")
        self.assertEqual(value, dict(value="FIRST ADDITIONAL ASSIGNMENTS KEY BANNER", number=2))
        self.assertFalse(any(call[0] in ("gcloud", "aws") for call in self.calls()))

    def test_force_beats_assignment_and_root_beats_import(self):
        config = self.root / "host.nix"
        config.write_text('{ lib, ... }: { value = "direct"; number = lib.mkForce 1; imports = [{ value = "imported"; }]; }')
        self.run_launcher(extra=["--config", str(config), "--set", "number=2"])
        self.assertEqual(self.evaluate(self.state / "config-payload"), dict(value="direct", number=1))
        unchanged = self.root / "without-assignments"
        self.run_launcher(extra=["--config", str(config)], state=unchanged)
        self.assertEqual(self.evaluate(unchanged / "config-payload"), dict(value="direct", number=1))

    def test_root_function_preserves_standard_custom_and_optional_arguments(self):
        config = self.root / "host.nix"
        config.write_text('''{ lib, config, options, custom, optional ? "default", ... }: {
          _module.args.custom = "module";
          value = "${custom}-${optional}";
          number = if config.value == "module-default" && options.number.default == 0 then 3 else 0;
        }''')
        self.run_launcher(extra=["--config", str(config)])
        self.assertEqual(self.evaluate(self.state / "config-payload"), dict(value="module-default", number=3))

    def test_assignments_encode_quotes_interpolation_and_file_contents(self):
        value = 'KEY ${throw "bad"} \\ newline\n'
        public_file = self.root / "public.txt"
        public_file.write_text(value)
        self.run_launcher(extra=["--set-file", "value=" + str(public_file), "--set", "number=4"])
        self.assertEqual(self.evaluate(self.state / "config-payload"), dict(value=value, number=4))

    def test_bundle_relative_imports_json_toml_and_original_source(self):
        source = self.root / "source"
        source.mkdir()
        (source / "data.json").write_text('{"value":"from-json"}')
        (source / "data.toml").write_text('number = 9\n')
        (source / "host.nix").write_text('{ imports = [ (builtins.fromJSON (builtins.readFile ./data.json)) (builtins.fromTOML (builtins.readFile ./data.toml)) ]; }')
        self.run_launcher(extra=["--config-root", str(source), "--config", str(source / "host.nix"), "--url-signer", "signer@example.invalid"])
        bundle = json.loads((self.state / "config-payload").read_text())
        extracted = self.root / "extracted"
        for path, contents in bundle["files"].items():
            output = extracted / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(base64.b64decode(contents))
        self.assertEqual(self.evaluate(extracted / bundle["entrypoint"], admitted_root=extracted), dict(value="from-json", number=9))
        self.assertEqual((extracted / "host.nix").read_bytes(), (source / "host.nix").read_bytes())

    def test_gcp_image_readiness_is_checked_before_launch(self):
        self.run_launcher(command="image-create")
        (self.root / "image-pending").touch()
        self.run_launcher(command="vm-create")
        self.assertTrue(any(call[0] == "sleep" for call in self.calls()))
        image_lists = [call for call in self.calls() if "images" in call and "list" in call]
        self.assertTrue(all("--no-standard-images" in call for call in image_lists))

        (self.root / "image-failed").touch()
        (self.root / "spot-deleted").touch()
        previous_launches = sum("instances" in call and "create" in call for call in self.calls())
        self.run_launcher(command="vm-create", success=False)
        self.assertEqual(sum("instances" in call and "create" in call for call in self.calls()), previous_launches)

    def test_missing_capability_fails_before_cloud_mutation(self):
        self.info["capabilities"]["configuration"] = []
        self.write_info()
        source = self.root / "source"
        source.mkdir()
        (source / "host.nix").write_text('{}')
        result = self.run_launcher(extra=["--config-root", str(source), "--config", str(source / "host.nix")], success=False)
        self.assertIn("lacks aos.config-bundle/v1", result.stderr)
        self.assertFalse(any(call[0] in ("gcloud", "aws") for call in self.calls()))

    def test_gcp_spot_import_preparation_and_delete_retains_image(self):
        self.run_launcher("up")
        calls = self.calls()
        self.assertTrue(any(call[:2] == ["sgdisk", "-e"] for call in calls))
        create = next(call for call in calls if call[0] == "gcloud" and "instances" in call and "create" in call)
        self.assertEqual(create[create.index("--provisioning-model") + 1], "SPOT")
        self.assertIn("nic-type=VIRTIO_NET", create[create.index("--network-interface") + 1])
        self.run_launcher("delete")
        resources = json.loads((self.state / "resources.json").read_text())
        self.assertTrue(resources["image"])
        self.assertFalse(resources["instance"])

    def test_reconciles_image_creation_and_spot_auto_deletion(self):
        self.run_launcher("up")
        resources = json.loads((self.state / "resources.json").read_text())
        resources["image"] = ""
        (self.state / "resources.json").write_text(json.dumps(resources))
        (self.root / "spot-deleted").touch()

        self.run_launcher("up")
        calls = self.calls()
        images = [call for call in calls if call[0] == "gcloud" and "images" in call and "create" in call]
        instances = [call for call in calls if call[0] == "gcloud" and "instances" in call and "create" in call]
        self.assertEqual(len(images), 1)
        self.assertEqual(len(instances), 2)

    def test_uploaded_image_resumes_after_provider_creation_failure(self):
        (self.root / "fail-image-create").touch()
        self.run_launcher("image-create", success=False)
        self.run_launcher("image-create")
        uploads = [call for call in self.calls() if call[0] == "gcloud" and "cp" in call and "--custom-metadata" in call]
        self.assertEqual(len(uploads), 1)

    def test_plain_function_and_quoted_assignment_path(self):
        config = self.root / "host.nix"
        config.write_text('args: { value = args.config.environment.etc."file.with.dots".text; number = 7; }')
        self.run_launcher(extra=["--config", str(config), "--set-string", 'environment.etc."file.with.dots".text=literal'])
        self.assertEqual(self.evaluate(self.state / "config-payload"), dict(value="literal", number=7))

    def test_aws_import_snapshot_register_uefi_and_spot(self):
        self.run_launcher("up", provider="aws")
        calls = self.calls()
        self.assertTrue(any("import-snapshot" in call for call in calls))
        self.assertFalse(any("import-image" in call for call in calls))
        register = next(call for call in calls if "register-image" in call)
        self.assertEqual(register[register.index("--boot-mode") + 1], "uefi")
        launch = next(call for call in calls if "run-instances" in call)
        self.assertIn("MarketType=spot", launch[launch.index("--instance-market-options") + 1])

    def resources(self):
        return json.loads((self.state / "resources.json").read_text())

    def banner(self, path):
        return self.evaluate(path, expression_result='evaluated.config.environment.etc."profile.local".text')

    def test_default_lifetime_starts_at_launch_and_survives_reuse(self):
        self.run_launcher("plan")
        self.assertNotIn("launch_token", self.resources())
        self.run_launcher("image-create")
        self.assertNotIn("deadline", self.resources())
        started = int(time.time())
        self.run_launcher("vm-create")
        state = self.resources()
        self.assertGreaterEqual(int(state["deadline_epoch"]), started + 86400)
        self.assertLessEqual(int(state["deadline_epoch"]), int(time.time()) + 86400)
        payload = (self.state / "launch-config").read_bytes()
        self.assertIn(state["deadline"], self.banner(self.state / "launch-config"))
        self.run_launcher("up")
        self.assertEqual(self.resources()["deadline"], state["deadline"])
        self.assertEqual(self.resources()["launch_token"], state["launch_token"])
        self.assertEqual((self.state / "launch-config").read_bytes(), payload)

    def test_on_demand_without_expiry_has_no_ephemeral_notice(self):
        options = ["--spot", "false", "--shutdown-after", "never"]
        plan = json.loads(self.run_launcher(extra=options).stdout)
        self.assertEqual(plan["capacity"], "on-demand")
        self.run_launcher("up", extra=options)
        launch = next(call for call in self.calls() if "instances" in call and "create" in call)
        self.assertEqual(launch[launch.index("--provisioning-model") + 1], "STANDARD")
        self.assertNotIn("--termination-time", launch)
        self.assertNotIn("--instance-termination-action", launch)
        self.assertNotIn("--maintenance-policy", launch)
        self.assertEqual(self.resources()["deadline"], "")
        files = self.evaluate(self.state / "launch-config", expression_result='builtins.attrNames evaluated.config.environment.etc')
        self.assertNotIn("profile.local", files)

    def test_on_demand_expiry_and_spot_without_expiry(self):
        self.run_launcher("up", extra=["--spot", "false", "--shutdown-after", "8m"])
        launch = next(call for call in self.calls() if "instances" in call and "create" in call)
        self.assertNotIn("--maintenance-policy", launch)
        self.assertEqual(launch[launch.index("--instance-termination-action") + 1], "DELETE")
        self.assertEqual(launch[launch.index("--termination-time") + 1], self.resources()["deadline"])
        self.assertNotIn("Spot capacity", self.banner(self.state / "launch-config"))
        self.run_launcher("delete")
        (self.state / "resources.json").unlink()
        self.run_launcher("up", extra=["--shutdown-after", "never"])
        notice = self.banner(self.state / "launch-config")
        self.assertIn("Spot capacity may end earlier", notice)
        self.assertIn("No automatic deletion", notice)

    def test_launch_retry_keeps_deadline_and_expired_attempt_is_rejected(self):
        (self.root / "fail-instance-create").touch()
        self.run_launcher("up", success=False)
        attempt = self.resources()
        payload = (self.state / "launch-config").read_bytes()
        self.run_launcher("vm-create")
        self.assertEqual(self.resources()["deadline"], attempt["deadline"])
        self.assertEqual(self.resources()["launch_token"], attempt["launch_token"])
        self.assertEqual((self.state / "launch-config").read_bytes(), payload)
        (self.root / "spot-deleted").touch()
        self.run_launcher("vm-create")
        self.assertNotEqual(self.resources()["launch_token"], attempt["launch_token"])

        self.run_launcher("delete")
        (self.root / "fail-instance-create").touch()
        self.run_launcher("vm-create", success=False)
        expired = self.resources()
        expired["deadline_epoch"] = int(time.time()) - 1
        (self.state / "resources.json").write_text(json.dumps(expired))
        creates = sum("instances" in call and "create" in call for call in self.calls())
        result = self.run_launcher("vm-create", success=False)
        self.assertIn("cannot be extended", result.stderr)
        self.assertEqual(sum("instances" in call and "create" in call for call in self.calls()), creates)

    def test_banner_preserves_notices_and_is_interactive_only(self):
        config = self.root / "host.nix"
        config.write_text('''{ aos.services.ssh.banner = "/etc/issue.net";
          environment.etc."profile.local".text = "# Existing site notice"; }''')
        self.run_launcher("up", extra=["--config", str(config)])
        result = self.evaluate(self.state / "launch-config", expression_result='''{
          banner = evaluated.config.aos.services.ssh.banner;
          site = evaluated.config.environment.etc."profile.local".text;
          notice = evaluated.config.environment.etc."profile.local".text;
        }''')
        self.assertEqual(result["banner"], "/etc/issue.net")
        self.assertTrue(result["site"].startswith("# Existing site notice"))
        self.assertIn(self.resources()["deadline"], result["notice"])
        quiet = subprocess.run(["bash", "-c", result["notice"]], env=self.env, text=True, capture_output=True)
        self.assertEqual(quiet.stdout, "")
        interactive = subprocess.run(["bash", "--noprofile", "--norc", "-ic", result["notice"]], env=self.env, text=True, capture_output=True)
        self.assertIn("Ephemeral AOS VM", interactive.stdout)

        config.write_text('{ lib, ... }: { environment.etc."profile.local".text = lib.mkForce "# Custom hook"; }')
        overridden = self.root / "forced-hook"
        self.run_launcher(extra=["--config", str(config)], state=overridden)
        self.assertEqual(self.banner(overridden / "config-payload"), "# Custom hook")

    def test_delete_recovers_lost_response_and_retains_unknown_attempt(self):
        for provider in ["gcp", "aws"]:
            with self.subTest(provider=provider):
                state = self.root / (provider + "-lost")
                (self.root / "lose-instance-response").touch()
                self.run_launcher("up", provider=provider, state=state, success=False)
                self.assertFalse(json.loads((state / "resources.json").read_text()).get("instance"))
                self.run_launcher("delete", provider=provider, state=state)
                self.assertEqual(json.loads((state / "resources.json").read_text())["launch_token"], "")
        self.run_launcher("image-create")
        (self.root / "fail-instance-create").touch()
        self.run_launcher("vm-create", success=False)
        token = self.resources()["launch_token"]
        result = self.run_launcher("delete", success=False)
        self.assertIn("unresolved", result.stderr)
        self.assertEqual(self.resources()["launch_token"], token)

    def test_aws_requires_role_and_on_demand_can_opt_out(self):
        self.run_launcher(provider="aws", extra=["--scheduler-role", ""], success=False)
        self.assertFalse(self.calls())
        self.run_launcher("up", provider="aws", extra=["--spot", "false", "--shutdown-after", "never", "--scheduler-role", ""])
        launch = next(call for call in self.calls() if "run-instances" in call)
        self.assertNotIn("--instance-market-options", launch)
        self.assertFalse(any("create-schedule" in call for call in self.calls()))

    def test_delete_clears_instance_id_before_a_new_lost_response(self):
        self.run_launcher("up")
        self.run_launcher("delete")
        self.assertFalse(self.resources()["instance_id"])

        (self.root / "lose-instance-response").touch()
        self.run_launcher("vm-create", success=False)
        remote_path = self.root / "gcp-instance.json"
        remote = json.loads(remote_path.read_text())
        remote["id"] = "new-instance-id"
        remote_path.write_text(json.dumps(remote))

        self.run_launcher("vm-create")
        self.assertEqual(self.resources()["instance_id"], "new-instance-id")
        self.assertEqual(sum("instances" in call and "create" in call for call in self.calls()), 2)

    def test_aws_schedule_and_cleanup_of_already_expired_resources(self):
        (self.root / "lose-schedule-response").touch()
        self.run_launcher("up", provider="aws")
        state = self.resources()
        schedule = json.loads((self.root / "schedule.json").read_text())
        self.assertEqual(schedule["ScheduleExpression"], "at(" + state["deadline"][:-1] + ")")
        self.assertEqual(json.loads(schedule["Target"]["Input"]), {"InstanceIds":[state["instance"]]})
        self.assertEqual(schedule["ActionAfterCompletion"], "DELETE")
        self.assertEqual(schedule["FlexibleTimeWindow"], {"Mode":"OFF"})
        (self.root / "schedule.json").unlink()
        (self.root / "aws-instance-missing").touch()
        self.run_launcher("delete", provider="aws")
        self.assertFalse(self.resources()["instance"])
        self.assertFalse(self.resources()["schedule"])

    def test_aws_schedule_failure_compensates_unfinished_instance(self):
        (self.root / "fail-schedule").touch()
        (self.root / "fail-terminate").touch()
        result = self.run_launcher("up", provider="aws", success=False)
        self.assertIn("cleanup failed", result.stderr)
        state = self.resources()
        self.assertTrue(state["instance"])
        self.assertEqual(state["launch_phase"], "launching")
        (self.root / "fail-terminate").unlink()
        result = self.run_launcher("vm-create", provider="aws", success=False)
        self.assertIn("was terminated", result.stderr)
        self.assertEqual(json.loads((self.root / "aws-instance.json").read_text())["State"]["Name"], "terminated")
        self.assertEqual(self.resources()["launch_token"], state["launch_token"])

    def test_aws_lost_response_and_filter_miss_keep_exact_metadata(self):
        config = self.root / "large.nix"
        config.write_text('{ value = "' + ('x' * 16000) + '"; }')
        (self.root / "lose-instance-response").touch()
        self.run_launcher("up", provider="aws", extra=["--config", str(config)], success=False)
        state = self.resources()
        metadata = (self.state / "user-data").read_bytes()
        presigns = sum("presign" in call for call in self.calls())
        self.run_launcher("vm-create", provider="aws", extra=["--config", str(config)])
        self.assertEqual(self.resources()["launch_token"], state["launch_token"])
        self.assertEqual((self.state / "user-data").read_bytes(), metadata)
        self.assertEqual(sum("presign" in call for call in self.calls()), presigns)
        (self.root / "miss-token-filter").touch()
        self.run_launcher("vm-create", provider="aws", extra=["--config", str(config)])
        self.assertEqual(sum("run-instances" in call for call in self.calls()), 1)
        (self.root / "aws-instance-missing").touch()
        self.run_launcher("vm-create", provider="aws", extra=["--config", str(config)], success=False)
        self.assertEqual(self.resources()["launch_token"], state["launch_token"])

    def test_rejects_changed_intent_and_unsafe_sources(self):
        self.run_launcher()
        self.run_launcher(extra=["--set", "number=2"], success=False)
        source = self.root / "source"
        source.mkdir()
        (source / "escape").symlink_to(self.key)
        self.run_launcher(extra=["--config-root", str(source)], success=False, state=self.root / "other")


if __name__ == "__main__":
    unittest.main()

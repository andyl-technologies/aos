##! Exercises native lower updates, image tombstones, and retained user changes.
{
  testing,
  pkgs,
}: let
  bootstrapScript = builtins.path {
    path = ../../pkgs/boot/_aos-boot-preparations/run-etc-setup.sh;
    name = "run-etc-setup.sh";
  };
in
  testing.mkVMTest {
    name = "native-configuration-lower";
    memory = 1024;
    rootfsDeps = [pkgs.aos-configuration-lower pkgs.python3 pkgs.erofs-utils pkgs.util-linux pkgs.coreutils bootstrapScript];
    testScript = ''
      set -eu
      # Match host propagation without changing the whole test root. Execute
      # the actual bootstrap, then reproduce PID 1's switch-root re-sharing.
      mkdir -p /run
      ${pkgs.util-linux}/bin/mount --bind /run /run
      ${pkgs.util-linux}/bin/mount --make-shared /run
      PATH=${pkgs.util-linux}/bin:${pkgs.util-linux}/sbin:${pkgs.coreutils}/bin \
        ${pkgs.bash}/bin/bash ${bootstrapScript}
      ${pkgs.util-linux}/bin/mount --make-rshared /run
      mkdir -p /tmp/image-etc /run/etc/system/metadata /run/etc/system/content \
        /run/etc/upper-initial/dir /run/etc/upper-initial/work /var/etc
      cp -a /etc/. /tmp/image-etc/
      mkdir -p /tmp/image-etc/app
      printf 'image baseline\n' > /tmp/image-etc/app/config
      ${pkgs.erofs-utils}/bin/mkfs.erofs --all-root -T0 /tmp/image-etc.erofs /tmp/image-etc
      ${pkgs.util-linux}/bin/mount -t erofs -o ro /tmp/image-etc.erofs /run/etc/system/metadata
      ${pkgs.util-linux}/bin/mount -t overlay overlay -o \
        lowerdir=/run/etc/system/metadata,upperdir=/run/etc/upper-initial/dir,workdir=/run/etc/upper-initial/work /etc
      ln -s upper-initial /run/etc/upper
      printf 'operator change\n' > /etc/user-edit

      ${pkgs.python3}/bin/python3 - <<'PY'
      import json
      import pathlib
      import subprocess
      import tempfile

      assembly = '${pkgs.aos-configuration-lower}/bin/aos-configuration-lower'
      mounting = '${pkgs.aos-configuration-lower}/bin/aos-configuration-mount'
      findmnt = '${pkgs.util-linux}/bin/findmnt'
      instance_effect = 'a' * 64
      persistent_effect = 'b' * 64
      persistent_text = 'persistent native configuration\n'
      previous_lower = None

      def propagation(path):
          return subprocess.check_output(
              [findmnt, '--noheadings', '--output', 'PROPAGATION', '--target', path],
              text=True,
          ).strip()

      assert propagation('/run') == 'shared'
      assert propagation('/run/etc') == 'shared'

      def effect(program, revision):
          return {
              'owner': 'os', 'identity': ['profile', 'system', 'lower'],
              'input': {}, 'inputs': {}, 'after': [], 'dependencies': [],
              'input_type': {'kind': 'submodule', 'open': False, 'fields': {}},
              'results': {}, 'revision': revision, 'lifetime': 'persistent', 'timeout_ms': 90000,
              'handler': {'kind': 'process', 'artifact': '${pkgs.aos-configuration-lower}', 'executable': program},
          }

      def call(program, action, value, revision, previous=None):
          invocation = {
              'id': 'native-lower-fixture', 'revision': revision,
              'action': 'remove' if action == 'remove' else 'apply',
              'previous': previous, 'input': value,
              'effect': effect(program, revision),
          }
          result = subprocess.run([program, action], input=json.dumps(invocation),
                                  text=True, capture_output=True, check=True)
          return json.loads(result.stdout)

      def install(content, revision, declare_persistent=False, retire_persistent=False):
          global previous_lower
          files = {} if content is None else {'app/config': {'kind': 'text', 'text': content, 'mode': '0444'}}
          file_effects = {} if content is None else {'app/config': {'id': instance_effect, 'lifetime': 'instance'}}
          if declare_persistent:
              files['app/persistent'] = {'kind': 'text', 'text': persistent_text, 'mode': '0640'}
              file_effects['app/persistent'] = {'id': persistent_effect, 'lifetime': 'persistent'}
          value = {'files': files, 'jobScripts': {}, 'removedPaths': [],
                   'baselinePaths': ['app/config'], 'ownership': {'files': {key: 'app' for key in files}, 'jobScripts': {}},
                   'fileEffects': file_effects, 'retiredEffects': [persistent_effect] if retire_persistent else [],
                   'storePaths': [], 'retainedRoot': '/var/lib/aos/configuration-lowers'}
          lower = call(assembly, 'apply', value, revision, previous=previous_lower)
          previous_lower = {
              'effect': effect(assembly, revision),
              'input': value, 'outputs': lower, 'revision': revision,
          }
          assert call(mounting, 'apply', lower, revision) == {'path': '/etc'}
          assert propagation('/run') == 'shared', 'publication changed the parent propagation'
          assert propagation('/run/etc') == 'private', 'publication left its staging parent shared'
          assert call(mounting, 'observe', lower, revision)['status'] == 'current'
          assert pathlib.Path('/etc/user-edit').read_text() == 'operator change\n'
          return lower

      def assert_persistent_file(path):
          assert path.read_text() == persistent_text, str(path)
          metadata = path.stat()
          assert metadata.st_mode & 0o7777 == 0o640, (str(path), metadata.st_mode)
          assert metadata.st_uid == 0 and metadata.st_gid == 0, (str(path), metadata)

      def assert_persistent_retained(lower):
          durable = pathlib.Path(lower['directory']) / 'etc-tree/app/persistent'
          assert_persistent_file(pathlib.Path('/etc/app/persistent'))
          assert_persistent_file(durable)
          assert str(durable).startswith('/var/lib/aos/configuration-lowers/'), str(durable)
          # Read the persisted image through a fresh read-only mount with no
          # overlay upper, proving the carried bytes survive upper recreation.
          with tempfile.TemporaryDirectory(dir='/run/etc') as image_mount:
              subprocess.run(['${pkgs.util-linux}/bin/mount', '-t', 'erofs', '-o', 'ro',
                              lower['image'], image_mount], check=True)
              try:
                  assert_persistent_file(pathlib.Path(image_mount) / 'app/persistent')
              finally:
                  subprocess.run(['${pkgs.util-linux}/bin/umount', image_mount], check=True)

      first = install('native first\n', 'first', declare_persistent=True)
      assert pathlib.Path('/etc/app/config').read_text() == 'native first\n'
      assert_persistent_retained(first)
      pathlib.Path('/etc/app/config').write_text('live configured update\n')
      pathlib.Path('/etc/app/config').unlink()
      assert not pathlib.Path('/etc/app/config').exists()

      removed = install(None, 'removed')
      assert not pathlib.Path('/etc/app/config').exists(), 'image baseline reappeared after removal'
      assert_persistent_retained(removed)
      readded = install('native re-added\n', 'readded')
      assert pathlib.Path('/etc/app/config').read_text() == 'native re-added\n'
      assert_persistent_retained(readded)
      call(mounting, 'remove', readded, 'readded')
      assert not pathlib.Path('/etc/app/config').exists(), 'prior lower was not restored'
      assert pathlib.Path('/etc/user-edit').read_text() == 'operator change\n'
      assert pathlib.Path('/etc/app/persistent').read_text() == persistent_text

      retired = install(None, 'retired', retire_persistent=True)
      assert not pathlib.Path('/etc/app/persistent').exists(), 'explicitly retired persistent file remains visible'
      assert not (pathlib.Path(retired['directory']) / 'etc-tree/app/persistent').is_file()
      settled = install(None, 'settled')
      assert not pathlib.Path('/etc/app/persistent').exists(), 'persistent file reappeared after retirement'
      assert not pathlib.Path('/etc/app/config').exists(), 'instance whiteout was lost after retirement'
      PY
    '';
  }

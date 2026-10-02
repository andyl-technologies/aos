##! Exercises native lower updates, image tombstones, and retained user changes.
{
  testing,
  pkgs,
}:
testing.mkVMTest {
  name = "native-configuration-lower";
  memory = 1024;
  rootfsDeps = [pkgs.aos-configuration-lower pkgs.python3 pkgs.erofs-utils pkgs.util-linux pkgs.coreutils];
  testScript = ''
    set -eu
    # Match host propagation without changing the whole test root. Execute
    # the actual bootstrap, then reproduce PID 1's switch-root re-sharing.
    mkdir -p /run
    ${pkgs.util-linux}/bin/mount --bind /run /run
    ${pkgs.util-linux}/bin/mount --make-shared /run
    PATH=${pkgs.util-linux}/bin:${pkgs.util-linux}/sbin:${pkgs.coreutils}/bin \
      ${pkgs.bash}/bin/bash ${../../pkgs/boot/_aos-boot-preparations/run-etc-setup.sh}
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

    assembly = '${pkgs.aos-configuration-lower}/bin/aos-configuration-lower'
    mounting = '${pkgs.aos-configuration-lower}/bin/aos-configuration-mount'
    findmnt = '${pkgs.util-linux}/bin/findmnt'

    def propagation(path):
        return subprocess.check_output(
            [findmnt, '--noheadings', '--output', 'PROPAGATION', '--target', path],
            text=True,
        ).strip()

    assert propagation('/run') == 'shared'
    assert propagation('/run/etc') == 'shared'

    def call(program, action, value, revision):
        invocation = {
            'id': 'native-lower-fixture', 'revision': revision,
            'action': 'remove' if action == 'remove' else 'apply',
            'previous': None, 'input': value,
            'effect': {
                'owner': 'os', 'identity': ['profile', 'system', 'lower'],
                'input': {}, 'inputs': {}, 'after': [], 'dependencies': [],
                'input_type': {'kind': 'submodule', 'open': False, 'fields': {}},
                'results': {}, 'revision': revision, 'lifetime': 'persistent', 'timeout_ms': 90000,
                'handler': {'kind': 'process', 'artifact': '${pkgs.aos-configuration-lower}', 'executable': program},
            },
        }
        result = subprocess.run([program, action], input=json.dumps(invocation),
                                text=True, capture_output=True, check=True)
        return json.loads(result.stdout)

    def install(content, revision):
        files = {} if content is None else {'app/config': {'kind': 'text', 'text': content, 'mode': '0444'}}
        value = {'files': files, 'jobScripts': {}, 'removedPaths': [],
                 'baselinePaths': ['app/config'], 'ownership': {'files': {key: 'app' for key in files}, 'jobScripts': {}},
                 'storePaths': [], 'retainedRoot': '/var/lib/aos/configuration-lowers'}
        lower = call(assembly, 'apply', value, revision)
        assert call(mounting, 'apply', lower, revision) == {'path': '/etc'}
        assert propagation('/run') == 'shared', 'publication changed the parent propagation'
        assert propagation('/run/etc') == 'private', 'publication left its staging parent shared'
        assert call(mounting, 'observe', lower, revision)['status'] == 'current'
        assert pathlib.Path('/etc/user-edit').read_text() == 'operator change\n'
        return lower

    first = install('native first\n', 'first')
    assert pathlib.Path('/etc/app/config').read_text() == 'native first\n'
    pathlib.Path('/etc/app/config').write_text('live configured update\n')
    pathlib.Path('/etc/app/config').unlink()
    assert not pathlib.Path('/etc/app/config').exists()

    removed = install(None, 'removed')
    assert not pathlib.Path('/etc/app/config').exists(), 'image baseline reappeared after removal'
    readded = install('native re-added\n', 'readded')
    assert pathlib.Path('/etc/app/config').read_text() == 'native re-added\n'
    call(mounting, 'remove', readded, 'readded')
    assert not pathlib.Path('/etc/app/config').exists(), 'prior lower was not restored'
    assert pathlib.Path('/etc/user-edit').read_text() == 'operator change\n'
    PY
  '';
}

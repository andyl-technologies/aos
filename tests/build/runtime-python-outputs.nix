##! Preserves Python integrations without retaining their interpreter in boot tools.
{pkgs}: let
  stubName =
    if pkgs.stdenv.hostPlatform.isx86_64
    then "linuxx64.efi.stub"
    else if pkgs.stdenv.hostPlatform.isAarch64
    then "linuxaa64.efi.stub"
    else throw "runtime Python output checks require a supported Linux architecture";
in
  pkgs.mkDerivation {
    pname = "runtime-python-outputs-check";
    version = "0";
    src = null;
    outputChecks = {};
    buildDeps = [pkgs.coreutils pkgs.binutils pkgs.jq pkgs.python3];
    exportReferencesGraph.runtime = [pkgs.systemd pkgs.util-linux pkgs.libcap-ng];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          if jq -er '.runtime[].path' "$NIX_ATTRS_JSON_FILE" | grep -E -- '-python3-[0-9]'; then
            echo "boot runtime still retains the Python interpreter" >&2
            exit 1
          fi

          export PYTHONPATH="${pkgs.util-linux.python}/lib/python3.14/site-packages:${pkgs.libcap-ng.python}/lib/python3.14/site-packages"
          ${pkgs.python3}/bin/python3 - <<'PY'
          import capng
          import libmount
          from pathlib import Path

          table_file = Path("test.fstab")
          table_file.write_text("/dev/qualification /qualification ext4 ro 0 0\n")
          table = libmount.Table().parse_file(str(table_file))
          entry = table.find_target("/qualification")
          assert entry is not None
          assert (entry.source, entry.fstype, entry.options) == ("/dev/qualification", "ext4", "ro")
          try:
              table.find_target("/missing")
          except libmount.Error:
              pass
          else:
              raise AssertionError("missing mount lookup unexpectedly succeeded")

          # These calls change only libcap-ng's in-memory capability set.
          # They do not apply capabilities to the build process or filesystem.
          capng.capng_clear(capng.CAPNG_SELECT_BOTH)
          assert capng.capng_have_capabilities(capng.CAPNG_SELECT_BOTH) == capng.CAPNG_NONE
          assert capng.capng_update(capng.CAPNG_ADD, capng.CAPNG_EFFECTIVE, capng.CAP_CHOWN) == 0
          assert capng.capng_have_capability(capng.CAPNG_EFFECTIVE, capng.CAP_CHOWN) == 1
          PY

          mkdir -p "$TMPDIR/kernel-config" "$TMPDIR/uki-staging"
          printf '%s\n' 'ID=aos' 'VERSION_ID=qualification' > "$TMPDIR/os-release"
          printf '[UKI]\nOSRelease=@%s\n' "$TMPDIR/os-release" > "$TMPDIR/kernel-config/uki.conf"
          printf '%s\n' 'console=ttyS0' > "$TMPDIR/kernel-config/cmdline"

          export KERNEL_INSTALL_CONF_ROOT="$TMPDIR/kernel-config"
          export KERNEL_INSTALL_STAGING_AREA="$TMPDIR/uki-staging"
          export KERNEL_INSTALL_ENTRY_TOKEN=aos-qualification
          export KERNEL_INSTALL_MACHINE_ID=00000000000000000000000000000001
          export KERNEL_INSTALL_LAYOUT=uki
          export KERNEL_INSTALL_IMAGE_TYPE=pe
          export KERNEL_INSTALL_BOOT_STUB="${pkgs.systemd}/lib/systemd/boot/efi/${stubName}"
          ${pkgs.systemd.tools}/lib/kernel/install.d/60-ukify.install \
            add ${pkgs.linux.version} "$TMPDIR/entry" \
            ${pkgs.linux}/boot/vmlinuz-${pkgs.linux.version}

          objcopy --dump-section .linux="$TMPDIR/observed-linux" "$TMPDIR/uki-staging/uki.efi"
          cmp "$TMPDIR/observed-linux" ${pkgs.linux}/boot/vmlinuz-${pkgs.linux.version}
          ${pkgs.systemd.tools}/bin/kernel-install --version > "$TMPDIR/kernel-install-version"

          mkdir -p "$out"
          cp "$TMPDIR/kernel-install-version" "$out/kernel-install-version"
          printf '%s\n' 'bindings and UKI construction passed; boot runtime excludes Python' > "$out/result"
        '';
      }
    ];
  }

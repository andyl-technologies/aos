# lib/testing/systemd-verity.nix — systemd dm-verity substrate check.
#
# Verifies the static userspace pieces RFC-0001 package RootImage= dm-verity
# roots need before renderer/VM work depends on them.
{
  pkgs,
  lib,
}:
pkgs.mkDerivation {
  pname = "systemd-verity-check";
  version = "0";
  src = null;

  buildDeps = [pkgs.grep];

  phases = [
    {
      name = "check";
      script = ''
        cryptsetup=${pkgs.cryptsetup}
        systemd=${pkgs.systemd}

        fail() {
          echo "FAIL: $*" >&2
          exit 1
        }

        test -x "$cryptsetup/sbin/veritysetup" \
          || fail "veritysetup is missing from cryptsetup"
        test -x "$systemd/lib/systemd/systemd-veritysetup" \
          || fail "systemd-veritysetup is missing"
        test -x "$systemd/lib/systemd/system-generators/systemd-veritysetup-generator" \
          || fail "systemd-veritysetup-generator is missing"
        test -f "$systemd/lib/systemd/system/veritysetup.target" \
          || fail "veritysetup.target is missing"
        test -f "$systemd/lib/systemd/system/remote-veritysetup.target" \
          || fail "remote-veritysetup.target is missing"

        "$cryptsetup/sbin/veritysetup" --help > veritysetup.help
        "$systemd/lib/systemd/systemd-veritysetup" --help > systemd-veritysetup.help

        grep -q -- 'format <data_device> <hash_device>' veritysetup.help \
          || fail "veritysetup lacks format action"
        grep -q -- 'verify <data_device> <hash_device>' veritysetup.help \
          || fail "veritysetup lacks verify action"
        grep -q -- '--root-hash-signature=STRING' veritysetup.help \
          || fail "veritysetup lacks root hash signature support"
        grep -q -- '^systemd-veritysetup attach ' systemd-veritysetup.help \
          || fail "systemd-veritysetup lacks attach action"

        core_lib=
        for candidate in "$systemd"/lib/systemd/libsystemd-core-*.so; do
          if grep -aq -- 'RootHashSignature' "$candidate"; then
            core_lib=$candidate
            break
          fi
        done
        test -n "$core_lib" \
          || fail "systemd core library lacks RootHashSignature parser strings"

        grep -aq -- 'RootImage' "$core_lib" \
          || fail "systemd manager lacks RootImage parser strings"
        grep -aq -- 'RootVerity' "$core_lib" \
          || fail "systemd manager lacks RootVerity parser strings"
        grep -aq -- 'RootHashSignature' "$core_lib" \
          || fail "systemd manager lacks RootHashSignature parser strings"

        mkdir -p "$out"
        {
          echo "cryptsetup=$cryptsetup"
          echo "veritysetup=$cryptsetup/sbin/veritysetup"
          echo "systemd=$systemd"
          echo "systemd-veritysetup=$systemd/lib/systemd/systemd-veritysetup"
          echo "systemd-veritysetup-generator=$systemd/lib/systemd/system-generators/systemd-veritysetup-generator"
        } > "$out/result"
      '';
    }
  ];

  meta.description = "Static check for systemd RootImage dm-verity support";
}

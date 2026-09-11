# Immutable SELinux warm root-handoff build contracts.
{
  lib,
  pkgs,
  system,
  ...
}: let
  stage0 = pkgs.aos-selinux-stage0;
  runtimeRootsProvisioner = pkgs.aos-selinux-runtime-roots;
  fixtureSystem.config = {
    system.build = {
      inherit (system.config.system.build) kernel systemdSystemPresets toplevel;
      immutableSelinuxPolicy = pkgs.aos-selinux-production-policy;
    };
    aos.boot.initrd.stage0 = stage0;
  };
  rootfs = (import ../../lib/build/rootfs.nix) {
    inherit lib pkgs;
    system = fixtureSystem;
    pname = "selinux-root-handoff-fixture";
    fsType = "erofs";
    erofsCompressionLevel = 1;
  };
in
  pkgs.mkDerivation {
    pname = "selinux-root-handoff-check";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.binutils
      pkgs.erofs-utils
      pkgs.python3
      rootfs
      stage0
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
            ${../../pkgs/security/aos-selinux-runtime-manifest_test.py}
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
            ${../../pkgs/security/aos-selinux-runtime-roots_source_test.py}
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
            ${../../pkgs/system/aos-systemd-rpath-sanitize_test.py}
          PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
            ${../../pkgs/filesystem/aos-device-mapper-rpath-sanitize_test.py}

          if ${pkgs.binutils}/bin/readelf -l \
            ${stage0}/bin/aos-selinux-stage0 | grep -q INTERP; then
            echo "stage0 root-handoff guard is dynamically linked" >&2
            exit 1
          fi
          if ${pkgs.binutils}/bin/readelf -d \
            ${stage0}/bin/aos-selinux-stage0 | grep -q NEEDED; then
            echo "stage0 root-handoff guard carries a dynamic dependency" >&2
            exit 1
          fi
          if ${pkgs.binutils}/bin/readelf -lW \
            ${runtimeRootsProvisioner}/bin/aos-selinux-runtime-roots \
            | grep -q INTERP; then
            echo "runtime-root provisioner is dynamically linked" >&2
            exit 1
          fi
          if ${pkgs.binutils}/bin/readelf -dW \
            ${runtimeRootsProvisioner}/bin/aos-selinux-runtime-roots \
            | grep -q NEEDED; then
            echo "runtime-root provisioner carries a dynamic dependency" >&2
            exit 1
          fi

          inner_guard_source=$(
            sed -n '/static void run_inner_guard(void)/,/^}/p' \
              ${../../pkgs/security/aos-selinux-stage0.c}
          )
          printf '%s\n' "$inner_guard_source" \
            | grep -F 'require_clean_loader_environment();'
          printf '%s\n' "$inner_guard_source" \
            | grep -F 'require_absent_loader_control_files();'

          manifest=${stage0}/share/aos-selinux-stage0/systemd_runtime_manifest.bin
          header=${stage0}/share/aos-selinux-stage0/systemd_runtime_manifest.h
          test -s "$manifest"
          grep -F '#define AOS_PHYSICAL_SYSTEMD_PATH "/nix.lower/store/' "$header"
          grep -F '#define AOS_PHYSICAL_INTERPRETER_PATH "/nix.lower/store/' "$header"
          grep -F '#define AOS_RUNTIME_ROOTS_PATH "/nix/store/' "$header"
          grep -F '#define AOS_PHYSICAL_RUNTIME_ROOTS_PATH "/nix.lower/store/' "$header"
          grep -F '#define AOS_EXPECTED_POLICY_SHA256 "' "$header"
          grep -F '#define AOS_RUNTIME_CLOSURE_DIGEST "' "$header"

          ${pkgs.python3}/bin/python3 -B -c '
          import hashlib, pathlib, sys

          fields = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
          assert fields[-1] == b"", fields[-1]
          assert fields[0] == b"AOS_AUTHENTICATED_RUNTIME_CLOSURE", fields[0]
          assert fields[1] == b"1", fields[1]
          assert fields[4].endswith(b"/bin/aos-selinux-runtime-roots"), fields[4]
          policy = pathlib.Path(
              "${stage0.expectedPolicy}"
          ).read_bytes()
          assert fields[5] == hashlib.sha256(policy).hexdigest().encode(), fields[5]
          count = int(fields[6])
          assert count > 0, count
          assert len(fields) == count + 9, (count, len(fields))
          assert fields[7:7 + count] == sorted(fields[7:7 + count]), fields
          digest_field = fields[-2]
          payload = b"\0".join(fields[:-2]) + b"\0"
          expected = hashlib.sha256(payload).hexdigest().encode()
          assert digest_field == expected, (digest_field, expected)
          ' "$manifest"

          mkdir extracted
          dump.erofs --extract=extracted ${rootfs}/root.img
          cmp \
            extracted/usr/lib/systemd/aos-selinux-root-handoff \
            ${stage0}/bin/aos-selinux-stage0
          test ! -s extracted/usr/lib/systemd/aos-empty-ld-so-preload
          if find extracted/usr/lib -name 'libtss2-tcti-*.so*' | grep -q .; then
            echo "constructed TCTI selector can reach an unpinned default-path DSO" >&2
            exit 1
          fi
          test ! -e extracted/usr/local/lib
          test ! -e extracted/lib64
          test ! -e extracted/usr/lib64

          ${pkgs.python3}/bin/python3 -B -c '
          import json, sys

          entries = {
              entry["path"]: entry
              for entry in json.load(open(sys.argv[1], encoding="utf-8"))["entries"]
          }
          guard = entries["/usr/lib/systemd/aos-selinux-root-handoff"]
          preload = entries["/usr/lib/systemd/aos-empty-ld-so-preload"]
          assert guard["kind"] == "regular", guard
          assert guard["context"].split(":", 3)[2] == "init_exec_t", guard
          assert preload["kind"] == "regular", preload
          assert preload["context"].split(":", 3)[2] == "lib_t", preload
          runtime_roots = entries[
              "/nix.lower/store/${builtins.baseNameOf runtimeRootsProvisioner}/bin/"
              "aos-selinux-runtime-roots"
          ]
          assert runtime_roots["kind"] == "regular", runtime_roots
          assert runtime_roots["context"].split(":", 3)[2] == \
              "aos_sandbox_runtime_roots_exec_t", runtime_roots
          ' ${rootfs}/rootfs-selinux-contexts.json
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/aos/selinux-root-handoff"
          cp \
            ${stage0}/share/aos-selinux-stage0/systemd_runtime_manifest.bin \
            ${stage0}/share/aos-selinux-stage0/systemd_runtime_manifest.h \
            "$out/share/aos/selinux-root-handoff/"
        '';
      }
    ];
  }

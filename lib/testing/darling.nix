# lib/testing/darling.nix — Darling-backed Darwin execution test specifications.
#
# Darling needs root privileges plus private mount and PID namespaces.  This
# helper deliberately produces an ordinary KVM fleet specification instead of
# running Darling in a Nix builder: the privileges stay inside a disposable AOS
# guest, while the existing fleet driver supplies boot supervision, command
# framing, timeouts, and retained serial/QEMU logs.
{
  pkgs,
  lib,
}: let
  validRelativeProgram = program: let
    components = lib.splitString "/" program;
  in
    program
    != ""
    && !(lib.hasPrefix "/" program)
    && builtins.all (component: component != "" && component != "." && component != "..") components;
in {
  # Produce a single-machine fleet specification that executes one x86_64
  # Mach-O program through Darling.  The caller's system remains responsible
  # for the Linux guest policy; this helper adds only the Darling runtime and
  # the exact target artifact closure under test.
  mkDarlingFleetSpec = {
    name,
    system,
    artifact,
    program,
    args ? [],
    darling ? pkgs.darling,
    expectedExitCode ? 0,
    expectedStdout ? null,
    expectedStderr ? null,
    timeout ? 900,
    bootTimeout ? 300,
    runtimeTimeout ? 120,
    memoryMiB ? 4096,
    payloadSizeMiB ? 256,
  }: let
    checkedProgram =
      if validRelativeProgram program
      then program
      else throw "mkDarlingFleetSpec: program must be a normalized relative path";
    checkedArgs =
      if builtins.all builtins.isString args
      then args
      else throw "mkDarlingFleetSpec: every argument must be a string";
    targetPath = "${artifact}/${checkedProgram}";
    targetArgsJson = builtins.toJSON checkedArgs;
    payloadDisk = pkgs.mkDerivation {
      pname = "aos-darling-payload-${name}";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.e2fsprogs
        pkgs.fakeroot
        pkgs.grep
      ];
      exportReferencesGraph = [
        "artifact-closure"
        artifact
        "darling-closure"
        darling
      ];
      phases = [
        {
          name = "build-payload";
          script = ''
            set -eu

            mkdir -p tree/nix/store "$out"
            grep -h '^/nix/store/' artifact-closure darling-closure \
              | sort -u > payload-paths
            while IFS= read -r store_path; do
              cp -a "$store_path" tree/nix/store/
            done < payload-paths

            truncate -s ${toString payloadSizeMiB}M "$out/payload.img"
            fakeroot mkfs.ext4 -q -F -L aos-darwin-run \
              -d tree "$out/payload.img"

            # Nix store paths cannot retain setuid mode bits. Apply the mode to
            # the filesystem image itself: Darling uses the transition only
            # inside the isolated guest to create private namespaces before
            # returning to the invoking user.
            debugfs -w -R \
              "set_inode_field ${darling}/bin/darling mode 0104755" \
              "$out/payload.img"
          '';
        }
      ];
    };
    guestSystem = system.extendModules {
      modules = [
        {
          # The payload disk carries Darling and the Mach-O closure. These are
          # ordinary guest tools needed to mount that read-only disk.
          # This extended system is a test fixture, so explicitly admit the
          # fleet control agent without weakening the production server image.
          aos.image.allowTestArtifacts = true;
          aos.packages.aos-test-agent = {
            package = pkgs.aos-test-agent;
            bundle = true;
            preset = false;
          };
          environment.systemPackages = [
            pkgs.bash
            pkgs.coreutils
            pkgs.util-linux
          ];
        }
      ];
    };
  in {
    inherit name timeout bootTimeout;

    machines.darwin = {
      system = guestSystem;
      # Boot the production UKI so the signed dm-verity identity tuple stays
      # intact. Direct-kernel fleet boot cannot safely synthesize roothash.
      bootMode = "image";
      imageDiskMiB = 12288;
      varProvisioning = "repart";
      extraDisks = [
        {
          serial = "darling-payload";
          sizeMiB = payloadSizeMiB;
          source = "${payloadDisk}/payload.img";
          readOnly = true;
        }
      ];
      inherit memoryMiB;
    };

    testScript =
      # python
      ''
        import json
        import shlex


        DARLING = "${darling}/bin/darling"
        DARLING_WARMUP = "${darling}/libexec/darling/usr/bin/plconvert"
        DARLING_STATE = "/run/aos-darling-state"
        DPREFIX = DARLING_STATE + "/prefix"
        RESULT_DIR = DARLING_STATE + "/result"
        RESULT_STATUS = RESULT_DIR + "/status"
        RESULT_STDOUT = RESULT_DIR + "/stdout"
        RESULT_STDERR = RESULT_DIR + "/stderr"
        RUNTIME_LOG = RESULT_DIR + "/runtime.log"
        PAYLOAD = "/run/aos-darling-payload"
        PAYLOAD_DEVICE = "/dev/disk/by-id/virtio-darling-payload"
        EXPECTED_EXIT = ${toString expectedExitCode}
        EXPECTED_STDOUT = json.loads(${builtins.toJSON (builtins.toJSON expectedStdout)})
        EXPECTED_STDERR = json.loads(${builtins.toJSON (builtins.toJSON expectedStderr)})
        TARGET_ARGS = json.loads(${builtins.toJSON targetArgsJson})

        def text_output(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return value

        darwin.wait_for_unit("multi-user.target", timeout=${toString bootTimeout})
        darwin.wait_until_succeeds(
            "test -b " + shlex.quote(PAYLOAD_DEVICE), timeout=30
        )
        # Darling's server traces sibling processes during syscall emulation.
        # Relax Yama only in this disposable test guest; the host and the
        # caller's production system configuration remain unchanged.
        darwin.succeed("echo 0 > /proc/sys/kernel/yama/ptrace_scope")
        darwin.succeed(
            "${pkgs.coreutils}/bin/mkdir -p "
            + " /run/user/65534 "
            + " /run/aos-darling-home "
            + shlex.quote(DARLING_STATE)
            + " "
            + shlex.quote(RESULT_DIR)
            + " "
            + shlex.quote(PAYLOAD)
        )
        darwin.succeed(
            "${pkgs.coreutils}/bin/chown -R 65534:65534 "
            + " /run/user/65534 /run/aos-darling-home "
            + shlex.quote(DARLING_STATE)
        )
        # Darling treats an absent DPREFIX as a first-run signal and creates
        # the writable overlay directories (including private/var/run) for the
        # invoking user. Precreating DPREFIX skips that initialization and
        # exposes the immutable runtime's 0555 directory, so shellspawn cannot
        # bind its socket.
        darwin.succeed("test ! -e " + shlex.quote(DPREFIX))
        darwin.succeed(
            "${pkgs.util-linux}/bin/mount -o ro "
            + shlex.quote(PAYLOAD_DEVICE)
            + " "
            + shlex.quote(PAYLOAD)
        )
        darwin.succeed(
            r"""
            set -eu
            for source in /run/aos-darling-payload/nix/store/*; do
              name=$(${pkgs.coreutils}/bin/basename "$source")
              target="/nix/store/$name"
              if [ -e "$target" ]; then
                continue
              fi
              ${pkgs.coreutils}/bin/mkdir -p "$target"
              ${pkgs.util-linux}/bin/mount --bind "$source" "$target"
              ${pkgs.util-linux}/bin/mount -o remount,bind,ro "$target"
            done
            """
        )
        launcher_mode = text_output(
            darwin.succeed(
                "${pkgs.coreutils}/bin/stat -c '%a %u:%g' "
                + shlex.quote(DARLING)
            )
        ).strip()
        assert launcher_mode == "4755 0:0", launcher_mode

        # launchd and darlingserver retain the first launcher's descriptors.
        # Warm the runtime with Darling's inert built-in converter so daemon
        # diagnostics go to their own log and the user artifact runs exactly
        # once with assertion-only stdout and stderr files.
        runner = (
            'darling="$1"; warmup="$2"; stdout="$3"; stderr="$4"; '
            'status_file="$5"; runtime_log="$6"; shift 6; '
            '"$darling" exec "$warmup" >>"$runtime_log" 2>&1 || true; '
            'status=0; "$darling" "$@" >"$stdout" 2>"$stderr" || status=$?; '
            'printf "%s\\n" "$status" >"$status_file"; '
            '"$darling" shutdown >>"$runtime_log" 2>&1 || true'
        )
        command = shlex.join(
            [
                "${pkgs.systemd}/bin/systemd-run",
                "--quiet",
                "--unit=aos-darling-runner",
                "--property=TimeoutStopSec=10s",
                "--uid=65534",
                "--gid=65534",
                "--setenv=HOME=/run/aos-darling-home",
                "--setenv=XDG_RUNTIME_DIR=/run/user/65534",
                "--setenv=DPREFIX=" + DPREFIX,
                "${pkgs.bash}/bin/bash",
                "-c",
                runner,
                "aos-darling-runner",
                DARLING,
                DARLING_WARMUP,
                RESULT_STDOUT,
                RESULT_STDERR,
                RESULT_STATUS,
                RUNTIME_LOG,
                "exec",
                ${builtins.toJSON targetPath},
            ]
            + TARGET_ARGS
        )
        darwin.succeed(command)
        darwin.wait_until_succeeds(
            "test -f " + shlex.quote(RESULT_STATUS),
            timeout=${toString runtimeTimeout},
        )
        # The wrapper requests Darling's normal shutdown. Stopping the scoped
        # transient unit is a bounded fallback that also reaps launchd if the
        # upstream shutdown command races the final emulated process.
        darwin.succeed(
            "${pkgs.systemd}/bin/systemctl stop aos-darling-runner.service"
        )

        status = int(
            text_output(
                darwin.succeed(
                    "${pkgs.coreutils}/bin/cat "
                    + shlex.quote(RESULT_STATUS)
                )
            ).strip()
        )
        stdout = text_output(
            darwin.succeed(
                "${pkgs.coreutils}/bin/cat " + shlex.quote(RESULT_STDOUT)
            )
        )
        stderr = text_output(
            darwin.succeed(
                "${pkgs.coreutils}/bin/cat " + shlex.quote(RESULT_STDERR)
            )
        )
        runtime_log = text_output(
            darwin.succeed(
                "${pkgs.coreutils}/bin/cat " + shlex.quote(RUNTIME_LOG)
            )
        )

        result = {
            "schema_version": "aos.darling-vm-result/v1",
            "program": "${artifact}/${checkedProgram}",
            "exit_code": status,
            "stdout": stdout,
            "stderr": stderr,
            "runtime_log": runtime_log,
        }
        print("DARLING_RESULT=" + json.dumps(result, sort_keys=True))

        assert status == EXPECTED_EXIT, result
        if EXPECTED_STDOUT is not None:
            assert stdout == EXPECTED_STDOUT, result
        if EXPECTED_STDERR is not None:
            assert stderr == EXPECTED_STDERR, result
      '';
  };
}

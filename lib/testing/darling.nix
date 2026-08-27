# lib/testing/darling.nix — Darling-backed Darwin execution test specifications.
#
# Darling needs root privileges plus private mount and PID namespaces. These
# helpers deliberately produce ordinary KVM fleet specifications instead of
# running Darling in a Nix builder: the privileges stay inside a disposable
# AOS guest, while the existing fleet driver supplies boot supervision,
# command framing, timeouts, and retained serial/QEMU logs.
{
  pkgs,
  lib,
}: let
  validCaseName = name:
    builtins.isString name
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name != null;

  validRelativeProgram = program: let
    components = lib.splitString "/" program;
  in
    builtins.isString program
    && program
    != ""
    && !(lib.hasPrefix "/" program)
    && builtins.all (component: component != "" && component != "." && component != "..") components;

  normalizeCase = rawCase:
    if !builtins.isAttrs rawCase
    then throw "mkDarlingFleetSuite: every case must be an attribute set"
    else if !(rawCase ? name) || !validCaseName rawCase.name
    then throw "mkDarlingFleetSuite: case name must match [A-Za-z0-9][A-Za-z0-9._-]*"
    else if !(rawCase ? artifact)
    then throw "mkDarlingFleetSuite: case ${rawCase.name} is missing artifact"
    else if !(rawCase ? program) || !validRelativeProgram rawCase.program
    then throw "mkDarlingFleetSuite: case ${rawCase.name} program must be a normalized relative path"
    else if !builtins.isList (rawCase.args or []) || !builtins.all builtins.isString (rawCase.args or [])
    then throw "mkDarlingFleetSuite: every argument for case ${rawCase.name} must be a string"
    else if !builtins.isInt (rawCase.expectedExitCode or 0)
    then throw "mkDarlingFleetSuite: expectedExitCode for case ${rawCase.name} must be an integer"
    else if !((rawCase.expectedStdout or null) == null || builtins.isString rawCase.expectedStdout)
    then throw "mkDarlingFleetSuite: expectedStdout for case ${rawCase.name} must be null or a string"
    else if !((rawCase.expectedStderr or null) == null || builtins.isString rawCase.expectedStderr)
    then throw "mkDarlingFleetSuite: expectedStderr for case ${rawCase.name} must be null or a string"
    else {
      inherit (rawCase) name artifact program;
      args = rawCase.args or [];
      expectedExitCode = rawCase.expectedExitCode or 0;
      expectedStdout = rawCase.expectedStdout or null;
      expectedStderr = rawCase.expectedStderr or null;
    };

  normalizeCases = rawCases:
    if !builtins.isList rawCases
    then throw "mkDarlingFleetSuite: cases must be a list"
    else if rawCases == []
    then throw "mkDarlingFleetSuite: cases must not be empty"
    else let
      normalized = builtins.map normalizeCase rawCases;
      names = builtins.map (testCase: testCase.name) normalized;
    in
      if builtins.length names != builtins.length (lib.unique names)
      then throw "mkDarlingFleetSuite: case names must be unique"
      else normalized;

  # Produce a single-machine fleet specification that executes multiple
  # x86_64 Mach-O programs through one Darling prefix. The caller's system
  # remains responsible for Linux guest policy; this helper adds only the
  # Darling runtime and exact target artifact closures under test.
  mkDarlingFleetSuite = {
    name,
    system,
    cases,
    darling ? pkgs.darling,
    timeout ? 900,
    bootTimeout ? 300,
    runtimeTimeout ? 300,
    memoryMiB ? 4096,
    payloadSizeMiB ? 256,
  }: let
    checkedCases = normalizeCases cases;
    serializedCases =
      builtins.map (testCase: {
        inherit (testCase) name args expectedExitCode expectedStdout expectedStderr;
        target = "${testCase.artifact}/${testCase.program}";
      })
      checkedCases;
    serializedCasesJson = builtins.toJSON serializedCases;
    artifactGraphs =
      lib.concatMap (testCase: [
        "artifact-${testCase.name}-closure"
        testCase.artifact
      ])
      checkedCases;
    graphFiles = lib.concatStringsSep " " (
      builtins.map (testCase: "artifact-${testCase.name}-closure") checkedCases
      ++ ["darling-closure"]
    );
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
      exportReferencesGraph =
        artifactGraphs
        ++ [
          "darling-closure"
          darling
        ];
      phases = [
        {
          name = "build-payload";
          script = ''
            set -eu

            mkdir -p tree/nix/store "$out"
            grep -h '^/nix/store/' ${graphFiles} \
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
          # The payload disk carries Darling and the Mach-O closures. These are
          # ordinary guest tools needed to mount that read-only disk. This
          # extended system is a test fixture, so explicitly admit the fleet
          # control agent without weakening the production server image.
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
        RUNTIME_LOG = RESULT_DIR + "/runtime.log"
        CASES_DONE = RESULT_DIR + "/cases.done"
        PAYLOAD = "/run/aos-darling-payload"
        PAYLOAD_DEVICE = "/dev/disk/by-id/virtio-darling-payload"
        CASES = json.loads(${builtins.toJSON serializedCasesJson})

        def text_output(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return value

        def result_path(case_name, suffix):
            return RESULT_DIR + "/" + case_name + "." + suffix

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
        # Warm one runtime, run every target exactly once with separate result
        # channels, then request shutdown after the full suite.
        runner = (
            'set -u; darling="$1"; warmup="$2"; result_dir="$3"; '
            'runtime_log="$4"; cases_done="$5"; shift 5; '
            '"$darling" exec "$warmup" >>"$runtime_log" 2>&1 || true; '
            'while [ "$#" -gt 0 ]; do '
            'case_name="$1"; argument_count="$2"; target="$3"; shift 3; '
            'arguments=(); argument_index=0; '
            'while [ "$argument_index" -lt "$argument_count" ]; do '
            'arguments+=("$1"); shift; argument_index=$((argument_index + 1)); done; '
            'stdout="$result_dir/$case_name.stdout"; '
            'stderr="$result_dir/$case_name.stderr"; '
            'status_file="$result_dir/$case_name.status"; status=0; '
            '"$darling" exec "$target" "''${arguments[@]}" '
            '>"$stdout" 2>"$stderr" || status=$?; '
            'printf "%s\\n" "$status" >"$status_file"; done; '
            'printf "done\\n" >"$cases_done"; '
            '"$darling" shutdown >>"$runtime_log" 2>&1 || true'
        )
        runner_arguments = [
            DARLING,
            DARLING_WARMUP,
            RESULT_DIR,
            RUNTIME_LOG,
            CASES_DONE,
        ]
        for case in CASES:
            runner_arguments.extend(
                [case["name"], str(len(case["args"])), case["target"]]
                + case["args"]
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
            ]
            + runner_arguments
        )
        darwin.succeed(command)
        darwin.wait_until_succeeds(
            "test -f " + shlex.quote(CASES_DONE),
            timeout=${toString runtimeTimeout},
        )
        # The wrapper requests Darling's normal shutdown. Stopping the scoped
        # transient unit is a bounded fallback that also reaps launchd if the
        # upstream shutdown command races the final emulated process.
        stop_status, stop_stdout, stop_stderr = darwin.execute(
            "${pkgs.systemd}/bin/systemctl stop aos-darling-runner.service"
        )
        # A completed transient unit is garbage-collected before this fallback
        # on the normal path. systemctl reports that benign state as exit 5.
        assert stop_status in (0, 5), (stop_status, stop_stdout, stop_stderr)

        runtime_log = text_output(
            darwin.succeed(
                "${pkgs.coreutils}/bin/cat " + shlex.quote(RUNTIME_LOG)
            )
        )
        results = []
        for case in CASES:
            status = int(
                text_output(
                    darwin.succeed(
                        "${pkgs.coreutils}/bin/cat "
                        + shlex.quote(result_path(case["name"], "status"))
                    )
                ).strip()
            )
            stdout = text_output(
                darwin.succeed(
                    "${pkgs.coreutils}/bin/cat "
                    + shlex.quote(result_path(case["name"], "stdout"))
                )
            )
            stderr = text_output(
                darwin.succeed(
                    "${pkgs.coreutils}/bin/cat "
                    + shlex.quote(result_path(case["name"], "stderr"))
                )
            )
            result = {
                "schema_version": "aos.darling-vm-result/v1",
                "case": case["name"],
                "program": case["target"],
                "exit_code": status,
                "stdout": stdout,
                "stderr": stderr,
                "runtime_log": runtime_log,
            }
            print("DARLING_RESULT=" + json.dumps(result, sort_keys=True))
            results.append(result)

        suite_result = {
            "schema_version": "aos.darling-vm-suite-result/v1",
            "name": ${builtins.toJSON name},
            "cases": results,
            "runtime_log": runtime_log,
        }
        print("DARLING_SUITE_RESULT=" + json.dumps(suite_result, sort_keys=True))

        for case, result in zip(CASES, results):
            assert result["exit_code"] == case["expectedExitCode"], result
            if case["expectedStdout"] is not None:
                assert result["stdout"] == case["expectedStdout"], result
            if case["expectedStderr"] is not None:
                assert result["stderr"] == case["expectedStderr"], result
      '';
  };

  # Backward-compatible one-program facade. It deliberately uses the same
  # suite engine so fixes to namespace setup, output isolation, and cleanup
  # apply uniformly to old and new callers.
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
  }:
    mkDarlingFleetSuite {
      inherit name system darling timeout bootTimeout runtimeTimeout memoryMiB payloadSizeMiB;
      cases = [
        {
          name = "target";
          inherit artifact program args expectedExitCode expectedStdout expectedStderr;
        }
      ];
    };
in {
  inherit mkDarlingFleetSpec mkDarlingFleetSuite;
}

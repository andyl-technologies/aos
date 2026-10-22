# Authenticated warm switch-root and daemon-reexec qualification.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
  enrolledFirmwareVarsPath = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
  stage0Fixture = import ./_selinux-stage0-fixture.nix {inherit lib pkgs;};
  postPinGate = "/run/aos/root-handoff-post-pin";
  qualificationStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = "";
  };
  postPinQualificationStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = "";
    qualificationPostPinGate = postPinGate;
  };
  systemdBasename = builtins.baseNameOf pkgs.systemd;
  glibcBasename = builtins.baseNameOf pkgs.glibc;
  libcapBasename = builtins.baseNameOf pkgs.libcap;
  dynamicLinker = pkgs.stdenv.hostPlatform.dynamicLinker;

  postPinAdversary = pkgs.mkDerivation {
    pname = "aos-root-handoff-post-pin-adversary";
    version = "1";
    src = null;
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            ${../sandbox/root-handoff-post-pin-adversary.c} \
            -o aos-root-handoff-post-pin-adversary
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-root-handoff-post-pin-adversary $out/bin/
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };
  postPinCommand = phase:
    "${postPinAdversary}/bin/aos-root-handoff-post-pin-adversary ${phase} "
    + "${systemdBasename} ${glibcBasename} ${libcapBasename} ${dynamicLinker}";

  custodySocket = {
    description = "AOS root-handoff descriptor custody socket";
    wantedBy = ["sockets.target"];
    # The switch-root isolation must preserve the descriptor being qualified.
    unitConfig.IgnoreOnIsolate = "yes";
    socketConfig = {
      ListenStream = "/run/aos-root-handoff-custody.sock";
      SocketMode = "0600";
      Service = "aos-root-handoff-custody.service";
    };
  };
  custodyService = {
    description = "AOS root-handoff descriptor custody sink";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/true";
    };
  };
  stateService = {
    description = "AOS root-handoff serialized state proof";
    wantedBy = ["basic.target"];
    unitConfig.IgnoreOnIsolate = "yes";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${pkgs.coreutils}/bin/true";
    };
  };
  postPinSwitchAdversary = {
    description = "Attack the parent mount namespace after switch-root pinning";
    requiredBy = ["initrd-switch-root.target"];
    # Isolation stops the setup services. Requiring them here restarts their
    # initrd dependencies inside the switch-root transaction and conflicts.
    after = ["nix-overlay-setup.service" "etc-overlay-setup.service"];
    before = ["initrd-switch-root.target"];
    unitConfig = {
      IgnoreOnIsolate = "yes";
      # Switch-root broadcasts SIGTERM after isolating the target. The attack
      # must remain alive until PID1 reaches the qualification-only pin gate.
      SurviveFinalKillSignal = true;
    };
    serviceConfig = {
      Type = "notify";
      ExecStart = postPinCommand "switch-root";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };
  postPinReexecAdversary = {
    description = "Attack the parent mount namespace after daemon-reexec pinning";
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "notify";
      ExecStart = postPinCommand "reexec";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };

  fixtureModule = mode: {
    config = lib.mkMerge [
      (stage0Fixture (
        if mode == "post-pin"
        then postPinQualificationStage0
        else qualificationStage0
      ))
      {
        aos.image.erofsCompressionLevel = 1;
        # The enforcing policy and complete runtime produce an 822 MiB root at
        # the fixture's fast compression level. Keep the 1 GiB root partitions
        # and bound the additional signed image payload separately from the base.
        aos.image.budgets = {
          maxRootMiB = 896;
          maxInitrdMiB = 224;
          maxBootExecutableMiB = 256;
          maxFirmwarePartitionMiB = 736;
          maxDownloadMiB = 1536;
        };

        # The production hold remains declared and unchanged. This signed test
        # image selects the normal initrd target through its qualification-only
        # stage0 build instead of weakening that production target.
        boot.initrd.systemd = {
          sockets.aos-root-handoff-custody = custodySocket;
          services = {
            aos-root-handoff-custody = custodyService;
            aos-root-handoff-state = stateService;
            aos-root-handoff-post-pin-adversary =
              lib.mkIf (mode == "post-pin") postPinSwitchAdversary;
            aos-root-handoff-custody-record = {
              description = "Record the pre-switch activation socket inode";
              requiredBy = ["initrd-switch-root.target"];
              after = ["aos-root-handoff-custody.socket"];
              before = ["initrd-switch-root.target"];
              serviceConfig = {
                Type = "oneshot";
                StandardOutput = "journal+console";
                StandardError = "journal+console";
              };
              script = ''
                set -eu
                inode="$(${pkgs.gawk}/bin/awk \
                  '$8 == "/run/aos-root-handoff-custody.sock" { print $7 }' \
                  /proc/net/unix)"
                test -n "$inode"
                printf '%s\n' "$inode" > /run/aos-root-handoff-custody.inode
                echo "AOS root-handoff custody before: inode=$inode"
              '';
            };
            aos-root-handoff-adversary =
              lib.mkIf (builtins.elem mode [
                "guard-substitution"
                "missing-runtime-root"
                "runtime-shadows"
              ]) {
                description = "Install qualification-only overlay shadow fixtures";
                requiredBy = ["initrd-switch-root.target"];
                after = ["nix-overlay-setup.service" "etc-overlay-setup.service"];
                before = ["initrd-switch-root.target"];
                serviceConfig = {
                  Type = "oneshot";
                  StandardOutput = "journal+console";
                  StandardError = "journal+console";
                };
                script =
                  if mode == "guard-substitution"
                  then ''
                    set -eu
                    printf '# invalid substituted guard\n' > /run/aos-substituted-guard
                    ${pkgs.coreutils}/bin/chmod 0555 /run/aos-substituted-guard
                    ${pkgs.util-linux}/bin/mount --bind \
                      /run/aos-substituted-guard \
                      /sysroot/usr/lib/systemd/aos-selinux-root-handoff
                    echo "AOS root-handoff adversary: substituted guard"
                  ''
                  else if mode == "missing-runtime-root"
                  then ''
                    set -eu
                    ${pkgs.coreutils}/bin/rm -rf \
                      /sysroot/nix/store/${libcapBasename}
                    printf 'AOS_WHITEOUTED_RUNTIME_ROOT\n' \
                      > /sysroot/nix/store/${libcapBasename}
                    echo "AOS root-handoff adversary: runtime root replaced by non-directory"
                  ''
                  else ''
                    set -eu
                    printf 'AOS_ATTACKER_SYSTEMD\n' > /run/aos-shadow-systemd
                    printf 'AOS_ATTACKER_LOADER\n' > /run/aos-shadow-loader
                    printf 'AOS_ATTACKER_DSO\n' > /run/aos-shadow-dso
                    printf '/run/aos-attacker-preload.so\n' > /run/aos-shadow-preload
                    ${pkgs.coreutils}/bin/chmod 0555 \
                      /run/aos-shadow-systemd /run/aos-shadow-loader /run/aos-shadow-dso

                    ${pkgs.util-linux}/bin/mount --bind /run/aos-shadow-systemd \
                      /sysroot/nix/store/${systemdBasename}/lib/systemd/systemd
                    ${pkgs.util-linux}/bin/mount --bind /run/aos-shadow-loader \
                      /sysroot/nix/store/${glibcBasename}/lib/${dynamicLinker}
                    ${pkgs.util-linux}/bin/mount --bind /run/aos-shadow-dso \
                      /sysroot/nix/store/${libcapBasename}/lib/libcap.so.2
                    ${pkgs.util-linux}/bin/mount --bind /run/aos-shadow-preload \
                      /sysroot/etc/ld.so.preload
                    echo "AOS root-handoff adversary: executable loader DSO and preload shadowed"
                  '';
              };
          };
        };

        systemd = {
          sockets.aos-root-handoff-custody = custodySocket;
          services = {
            aos-root-handoff-custody = custodyService;
            aos-root-handoff-state = stateService;
            aos-root-handoff-post-pin-adversary =
              lib.mkIf (mode == "post-pin") postPinReexecAdversary;
          };
        };
      }
    ];
  };

  systemFor = mode: let
    selected = systems.server-secureboot-lockdown.extendModules {
      modules = [../../systems/_server-test-packages.nix (fixtureModule mode)];
    };
  in
    # Fail during evaluation if qualification wiring disappears before image
    # assembly; an ordinary boot cannot qualify the authenticated handoff.
    assert selected.config.aos.boot.initrd.stage0 != null;
    assert builtins.all (parameter: builtins.elem parameter selected.config.aos.boot.kernelParams)
    ["selinux=1" "security=selinux" "enforcing=1" "aos.selinux.root_handoff=1"]; selected;
  cleanSystem = systemFor "clean";
  shadowSystem = systemFor "runtime-shadows";
  guardSubstitutionSystem = systemFor "guard-substitution";
  missingRuntimeRootSystem = systemFor "missing-runtime-root";
  postPinSystem = systemFor "post-pin";
in {
  name = "selinux-enforcing-root-handoff";
  timeout = 2400;
  bootTimeout = 300;

  machines = {
    clean = {
      system = cleanSystem;
      bootMode = "image";
      firmwareVars = enrolledFirmwareVarsPath;
    };
    shadows = {
      system = shadowSystem;
      bootMode = "image";
      firmwareVars = enrolledFirmwareVarsPath;
    };
    postPin = {
      system = postPinSystem;
      bootMode = "image";
      firmwareVars = enrolledFirmwareVarsPath;
    };
    substitutedGuard = {
      system = guardSubstitutionSystem;
      bootMode = "image";
      firmwareVars = enrolledFirmwareVarsPath;
      expectAgent = false;
    };
    missingRuntimeRoot = {
      system = missingRuntimeRootSystem;
      bootMode = "image";
      firmwareVars = enrolledFirmwareVarsPath;
      expectAgent = false;
    };
  };

  testScript =
    # python
    ''
      import time
      from pathlib import Path

      def await_serial(machine, marker):
          deadline = time.monotonic() + 180
          transcript = ""
          stable_since = None
          serial_log = Path(machine.serial_log_path)
          while time.monotonic() < deadline:
              if serial_log.exists():
                  observed = serial_log.read_text(errors="replace")
                  if marker in observed:
                      if observed != transcript:
                          transcript = observed
                          stable_since = time.monotonic()
                      elif stable_since is not None and time.monotonic() - stable_since >= 3:
                          return transcript
              time.sleep(1)
          raise AssertionError(f"timed out waiting for {marker!r}:\n{transcript[-16000:]}")

      def prove_custody(machine):
          before = machine.succeed("cat /run/aos-root-handoff-custody.inode").strip()
          after = machine.succeed(
              "awk '$8 == \"/run/aos-root-handoff-custody.sock\" { print $7 }' /proc/net/unix"
          ).strip()
          assert before == after, (before, after)
          machine.succeed("systemctl is-active aos-root-handoff-state.service")
          return before

      for machine in (clean, shadows):
          machine.wait_for_unit("multi-user.target")
          marker = machine.succeed("cat /run/aos/selinux-root-handoff")
          assert "version=1" in marker
          assert "phase=switch-root" in marker
          assert "systemd=/usr/lib/aos/nix/store/" in marker
          assert "manifest_sha256=" in marker
          inode = prove_custody(machine)

          machine.succeed("systemctl daemon-reexec")
          machine.wait_for_unit("multi-user.target")
          marker = machine.succeed("cat /run/aos/selinux-root-handoff")
          assert "phase=reexec" in marker
          assert prove_custody(machine) == inode

      postPin.wait_for_unit("multi-user.target")
      postPin.succeed("test -s /run/aos/post-pin-switch-root.done")
      postPin.succeed(
          "! grep -q AOS_POST_PIN_ATTACKER_SYSTEMD "
          "/nix/store/${systemdBasename}/lib/systemd/systemd"
      )
      postPin.succeed(
          "! grep -q AOS_POST_PIN_ATTACKER_LOADER "
          "/nix/store/${glibcBasename}/lib/${dynamicLinker}"
      )
      postPin.succeed(
          "! grep -q AOS_POST_PIN_ATTACKER_DSO "
          "/nix/store/${libcapBasename}/lib/libcap.so.2"
      )
      postPin.succeed("test ! -s /etc/ld.so.preload")

      postPin.wait_for_unit("aos-root-handoff-post-pin-adversary.service")
      postPin.succeed("touch /run/aos/post-pin-reexec.arm")
      postPin.succeed("systemctl daemon-reexec")
      postPin.wait_for_unit("multi-user.target")
      postPin.succeed("test -s /run/aos/post-pin-reexec.done")
      marker = postPin.succeed("cat /run/aos/selinux-root-handoff")
      assert "phase=reexec" in marker
      postPin.succeed(
          "! grep -q AOS_POST_PIN_ATTACKER_SYSTEMD "
          "/nix/store/${systemdBasename}/lib/systemd/systemd"
      )
      postPin.succeed(
          "! grep -q AOS_POST_PIN_ATTACKER_LOADER "
          "/nix/store/${glibcBasename}/lib/${dynamicLinker}"
      )
      postPin.succeed(
          "! grep -q AOS_POST_PIN_ATTACKER_DSO "
          "/nix/store/${libcapBasename}/lib/libcap.so.2"
      )
      postPin.succeed("test ! -s /etc/ld.so.preload")

      shadows.succeed(
          "! grep -q AOS_ATTACKER_SYSTEMD /nix/store/${systemdBasename}/lib/systemd/systemd"
      )
      shadows.succeed(
          "! grep -q AOS_ATTACKER_LOADER /nix/store/${glibcBasename}/lib/${dynamicLinker}"
      )
      shadows.succeed(
          "! grep -q AOS_ATTACKER_DSO /nix/store/${libcapBasename}/lib/libcap.so.2"
      )
      shadows.succeed("test ! -s /etc/ld.so.preload")

      failure = await_serial(
          substitutedGuard,
          "Authenticated AOS root-handoff guard is unavailable",
      )
      assert "AOS root-handoff adversary: substituted guard" in failure
      assert "AOS SELinux stage0: runtime closure pinned" not in failure
      assert "trying fallback" not in failure
      assert "fallback shell" not in failure

      pin_failure = await_serial(
          missingRuntimeRoot,
          "is missing, whiteouted, or not a directory",
      )
      assert "runtime root replaced by non-directory" in pin_failure
      assert "trying fallback" not in pin_failure
      assert "fallback shell" not in pin_failure
    '';
}

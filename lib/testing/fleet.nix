# lib/testing/fleet.nix — Multi-VM test orchestrator (QEMU-only).
#
# Each machine boots through the production initrd path (stage-1 systemd
# → systemd-repart substrate → switch-root → stage-2 systemd). Per-machine
# identity (hostname, /etc/hosts, eth0 .network, the guest-agent unit) is
# baked into the image's /etc via `extendModules`. Tests may additionally
# attach a read-only `aos-metadata` ISO to exercise the production
# cloud-metadata provisioning path.
# Inter-VM L2 is QEMU's `-netdev socket,mcast=…` transport — host-local
# UDP multicast carrying Ethernet frames — so no host bridge or tap setup
# is required. CAP_NET_ADMIN is not needed.
#
# Drivers: QEMU only. Single-VM tests use Firecracker via mkVMTest in
# lib/testing/vm.nix; the two harnesses are deliberately segregated by
# transport (vsock vs. virtio-serial) and don't share driver state.
#
# This module exposes two builders:
#   - `mkFleetTest spec`              — sandboxed test with PING/SHUTDOWN
#                                       agent orchestration. Used by
#                                       `aos test fleet <suite>`.
#   - `mkFleetTestInteractive {…}`    — outside-sandbox launcher with a
#                                       second user-mode NIC + hostfwd:22
#                                       and an SSH-key baked into the image
#                                       /etc. Reachable via
#                                       `aos test fleet <suite> --interactive
#                                                  --ssh-authorized-key …`.
#
# `mkFleetTest`'s returned derivation also carries a `.driverInteractive`
# attribute that, when applied to a pubkey string, produces the matching
# interactive build — analogous to nixpkgs' `passthru.driverInteractive`.
{
  pkgs,
  lib,
}: let
  vmLib = import ./vm.nix {inherit pkgs lib;};
  # ── MAC scheme (mirrors NixOS qemu-common.nix) ─────────────────────
  # 52:54:00:12:<vlan>:<machine>. The fleet's primary mcast NIC uses
  # vlan byte 0 (in keeping with the original convention here). The
  # interactive harness's user-mode NIC uses vlan byte 1 to keep it
  # in a distinct address range — same prefix, different vlan, no
  # accidental collision with the fleet NIC.
  zeroPad = n:
    if n > 255
    then throw "fleet: machine number ${toString n} > 255"
    else lib.optionalString (n < 16) "0" + lib.toHexString n;
  mkMac = vlan: n: "52:54:00:12:${zeroPad vlan}:${zeroPad n}";

  uriEncode = lib.uriEncode;
  dataUrl = content: "data:,${uriEncode content}";

  # ── Per-machine derivation order ───────────────────────────────────
  # Drives IP, MAC, banner ordering. `lib.imap` is the AOS lib's
  # 0-indexed iterator (lib/lists.nix:97). `debugMac` is allocated
  # whether or not interactive mode is enabled — it's cheap (string
  # interpolation only) and keeping it as a stable per-machine field
  # avoids parameterising downstream helpers on the mode.
  #
  # The guest agent reaches every fleet machine one of two ways: baked
  # into the /var seed (kernel boot + `varProvisioning = "baked"`, the
  # default), or delivered through the bundled `aos-test-agent` package
  # for image/repart boots that ship no seed. The driver waits on every
  # machine's agent, so a
  # machine that bakes no seed always needs that package. Inject it here
  # rather than making each test name it: agent delivery is a harness
  # concern, not a property of the machine under test.
  mkMachinesWithIndex = machines: let
    machineNames = builtins.attrNames machines;
  in
    lib.imap (i: mname: let
      m = machines.${mname};
      bootMode = m.bootMode or "kernel";
      varProvisioning = m.varProvisioning or "baked";
      packages = m.packages or [];
      # `baked` /var seeds the agent at build time; every other shape
      # relies on a baked `systemd.services.aos-test-agent` unit.
      bakesAgent = bootMode == "kernel" && varProvisioning == "baked";
      agentBundled = m.system.config.aos.packages.aos-test-agent.bundle or false;
      packagesWithAgent =
        if bakesAgent || builtins.elem "aos-test-agent" packages
        then packages
        else if agentBundled
        then packages ++ ["aos-test-agent"]
        else
          throw ''
            fleet: machine "${mname}" boots without a baked /var seed
            (bootMode = "${bootMode}", varProvisioning = "${varProvisioning}"),
            so the test guest agent must arrive via the aos-test-agent package
            — but that package is not bundled on its system. Set
            `aos.packages.aos-test-agent.bundle = true` on the machine's system
            (the server profile already does).
          '';
    in {
      inherit (m) system;
      inherit bootMode varProvisioning bakesAgent;
      packages = packagesWithAgent;
      # `extraClosures` / `varSizeMiB` / `imageDiskMiB` default on the
      # fleet machine type, so the `or` fallbacks only matter for callers
      # bypassing fleet-spec validation.
      extraModules = m.extraModules or [];
      extraClosures = m.extraClosures or [];
      metadata = m.metadata or {};
      varSizeMiB = m.varSizeMiB or 256;
      imageDiskMiB = m.imageDiskMiB or 40960;
      extraDisks = m.extraDisks or [];
      expectAgent = m.expectAgent or true;
      memoryMiB = m.memoryMiB or 2048;
      tpm = m.tpm or false;
      name = mname;
      ip = "192.168.50.${toString (i + 10)}";
      mac = mkMac 0 (i + 1);
      debugMac = mkMac 1 (i + 1);
      index = i;
    })
    machineNames;

  # /etc/hosts entries seen by every machine — every guest sees every
  # other guest by name. Test scripts use this implicitly
  # (curl http://server:8000/).
  mkHostsEntries = machinesWithIndex:
    lib.concatStringsSep "\n"
    (builtins.map (m: "${m.ip} ${m.name}") machinesWithIndex);

  # ── Per-machine identity module (baked via extendModules) ──────────
  # Bakes each machine's identity into the image.
  # Instead of delivering hostname / hosts / .network / ssh-key / agent-unit
  # over a metadata channel at first boot, they are baked straight into the
  # machine image's `/etc` (the system EROFS, gen-0) by overlaying this module
  # onto the machine's already-evaluated system with `extendModules`. On the
  # the initrd `aos-config-seed` leaves the per-generation `/etc` lower empty,
  # so all of `/etc` comes from this baked EROFS — exactly what these entries
  # populate. The same module uses the production systemd-repart substrate.
  #
  #   `bakeAgentUnit` — emit `systemd.services.aos-test-agent` here. False for
  #   `baked`-var kernel machines, whose /var seed already carries the unit
  #   (avoids a duplicate unit definition); true for image / repart machines
  #   that ship no baked seed.
  #   `sshAuthorizedKey` — non-null only in the interactive launcher; adds the
  #   root pubkey (mode 0600) and a DHCP .network for the debug NIC.
  mkNewpathModule = {
    m,
    hostsEntries,
    bakeAgentUnit,
    sshAuthorizedKey ? null,
  }: {
    lib,
    pkgs,
    config,
    ...
  }: let
    agentPackage = config.aos.packages.aos-test-agent.package or pkgs.aos-test-agent;
    agentPath = "${agentPackage}/share/aos-test-agent/aos-test-agent";
  in {
    # Fleet machines are driven through the guest agent (virtio-serial), never
    # an interactive serial console. The debug profile's initrd serial debug
    # shell runs `agetty --autologin` on ttyS0 with TTYVHangup, which corrupts
    # the serial log the harness captures and obscures stage-1 boot output.
    # Mask it (harmless if the debug profile isn't present).
    boot.initrd.systemd.maskedUnits = ["debug-shell-serial.service"];

    # Image-boot machines take their cmdline from the UKI, not the driver's
    # `-append`; match the kernel-boot append so the serial log stays
    # informative (`forward_to_console` — systemd unit progress after journald
    # starts) and NICs enumerate deterministically as ethN (`net.ifnames=0`).
    aos.boot.kernelParams = [
      "systemd.journald.forward_to_console=1"
      "net.ifnames=0"
    ];

    aos.networking.hostName = m.name;

    environment.etc =
      {
        "hosts".text = ''
          127.0.0.1 localhost
          ${hostsEntries}
        '';
        "systemd/network/10-fleet-eth0.network".text = ''
          [Match]
          MACAddress=${m.mac}

          [Network]
          Address=${m.ip}/24
        '';
      }
      // lib.optionalAttrs (m.packages != []) {
        "aos/packages.d/fleet-seed".text =
          lib.concatMapStrings (p: "${p}\n") m.packages;
      }
      // lib.optionalAttrs (sshAuthorizedKey != null) {
        "ssh/authorized_keys/root" = {
          text = "${sshAuthorizedKey}\n";
          mode = "0600";
        };
        "systemd/network/20-debug-eth1.network".text = ''
          [Match]
          MACAddress=${m.debugMac}

          [Network]
          DHCP=ipv4
        '';
      };

    systemd.services = lib.optionalAttrs bakeAgentUnit {
      "aos-test-agent" = {
        description = "AOS VM Test Guest Agent";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "simple";
          ExecStart = agentPath;
          Restart = "on-failure";
          RestartSec = 1;
          Environment = "PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
        };
      };
    };
  };

  # Bake per-machine identity and optional debug access into the effective
  # system. Used for image/kernel/initrd/disk.
  mkEffectiveSystem = {
    m,
    hostsEntries,
    sshAuthorizedKey ? null,
  }:
    m.system.extendModules {
      modules =
        [
          (mkNewpathModule {
            inherit m hostsEntries sshAuthorizedKey;
            bakeAgentUnit =
              (!m.bakesAgent) && builtins.elem "aos-test-agent" m.packages;
          })
        ]
        ++ m.extraModules;
    };

  # ── Per-machine builds ─────────────────────────────────────────────
  # `disk` is a function of `{system, extraClosures, varSizeMiB}`.
  # Nix dedups identical derivations, so two machines with matching
  # image inputs reference one disk.
  # `metadataISO` is an optional per-machine derivation containing only the
  # files explicitly declared by the test spec.
  mkMachineBuilds = {
    machinesWithIndex,
    hostsEntries,
    sshAuthorizedKey ? null,
  }:
    builtins.map (
      m: let
        # Every machine bakes per-VM identity into its image /etc. A test may
        # independently attach provisioning input through the metadata channel.
        effectiveSystem = mkEffectiveSystem {inherit m hostsEntries sshAuthorizedKey;};
        metadataNames = builtins.attrNames m.metadata;
        invalidMetadataNames =
          builtins.filter
          (name: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name == null)
          metadataNames;
        metadataFiles =
          builtins.map
          (name: {
            inherit name;
            source = pkgs.writeTextFile {
              name = "aos-fleet-${m.name}-metadata-${name}";
              text = m.metadata.${name};
              destination = "/value";
            };
          })
          metadataNames;
        metadataISO =
          if invalidMetadataNames != []
          then
            throw ''
              fleet: machine "${m.name}" has invalid metadata file names:
              ${lib.concatStringsSep ", " invalidMetadataNames}
              Metadata entries must be plain file names containing only
              letters, digits, dot, underscore, and hyphen.
            ''
          else if metadataFiles == []
          then null
          else
            pkgs.runCommand "aos-fleet-${m.name}-metadata" {
              buildDeps = [pkgs.libisoburn];
            } ''
              mkdir -p "$out/tree"
              ${lib.concatMapStringsSep "\n" (file: ''
                  cp ${file.source}/value "$out/tree/${file.name}"
                '')
                metadataFiles}
              ${pkgs.libisoburn}/bin/xorriso -as mkisofs \
                -V aos-metadata \
                -o "$out/metadata.iso" \
                "$out/tree"
            '';
      in
        {
          inherit (m) name ip mac debugMac index packages bootMode tpm varProvisioning varSizeMiB memoryMiB extraDisks expectAgent;
          inherit metadataISO;
          system = effectiveSystem;
        }
        // (
          if m.bootMode == "image"
          then {
            inherit (m) imageDiskMiB;
            image = effectiveSystem.config.system.build.image.raw;
            imageName = "aos-${effectiveSystem.config.aos.system.name}.img";
          }
          else {
            kernel = effectiveSystem.config.system.build.kernel;
            initrd = effectiveSystem.config.system.build.initrd;
            disk = vmLib.mkTestDisk {
              system = effectiveSystem;
              inherit (m) extraClosures varSizeMiB varProvisioning;
            };
          }
        )
    )
    machinesWithIndex;

  # ============================================================
  # mkFleetTest — sandboxed test launcher (the original entry point).
  # ============================================================
  mkFleetTest = spec: let
    # spec is already validated against fleetSpecType by the discoverer
    # — including the per-machine `packages` enum-against-`config.aos.packages`.
    inherit (spec) name testScript timeout machines;
    bootTimeout = spec.bootTimeout or null;

    machinesWithIndex = mkMachinesWithIndex machines;
    hostsEntries = mkHostsEntries machinesWithIndex;
    machineBuilds = mkMachineBuilds {inherit machinesWithIndex hostsEntries;};

    # Driver manifest. One entry per fleet machine; transport pinned to
    # qemu. The driver consumes this JSON and starts each VM in order,
    # then exposes each machine to the testScript as a Python global
    # named after `mb.name` (e.g. controlplane, worker). Per-machine RAM
    # comes from the spec's `memoryMiB` (default 2 GiB); vCPU count is a
    # uniform 2 per machine.
    manifest =
      {
        inherit name timeout;
      }
      // (lib.optionalAttrs (bootTimeout != null) {boot_timeout = bootTimeout;})
      // {
        machines =
          builtins.map (
            mb:
              {
                inherit (mb) name mac ip;
                transport = "qemu";
                memory_mib = mb.memoryMiB;
                vcpu_count = 2;
                # vTPM (RFC-0006 phase 3): when set, the driver launches a
                # per-machine swtpm and wires QEMU's tpm-tis to it.
                tpm = mb.tpm;
                expect_agent = mb.expectAgent;
                extra_disks = mb.extraDisks;
                swtpm_bin = "${pkgs.swtpm}/bin/swtpm";
              }
              // (
                if mb.bootMode == "image"
                then {
                  boot = "image";
                  disk = "${builtins.toString mb.image}/${mb.imageName}";
                  disk_size_mib = mb.imageDiskMiB;
                  # Identity is baked into the image /etc, so no fw_cfg channel.
                  fw_cfg = null;
                  firmware_code = "${pkgs.edk2}/FV/OVMF_CODE.fd";
                  firmware_vars = "${pkgs.edk2}/FV/OVMF_VARS.fd";
                  metadata =
                    if mb.metadataISO == null
                    then null
                    else "${builtins.toString mb.metadataISO}/metadata.iso";
                }
                else
                  {
                    boot = "kernel";
                    kernel = builtins.toString mb.kernel;
                    initrd = "${builtins.toString mb.initrd}/initrd.img";
                    disk = "${builtins.toString mb.disk}/disk.img";
                    metadata =
                      if mb.metadataISO == null
                      then null
                      else "${builtins.toString mb.metadataISO}/metadata.iso";
                  }
                  // (lib.optionalAttrs (mb.varProvisioning == "repart") {
                    # Base disk ships no /var; grow the per-run copy by this
                    # many MiB so systemd-repart has room to create /var on first boot
                    # (driver: aos_test_driver/qemu.py).
                    var_size_mib = mb.varSizeMiB;
                  })
              )
          )
          machineBuilds;
      };
    manifestFile = pkgs.writeTextFile {
      name = "aos-fleet-test-${name}-manifest.json";
      text = builtins.toJSON manifest;
      destination = "/manifest.json";
    };
    testPyFile = pkgs.writeTextFile {
      name = "aos-fleet-test-${name}-test.py";
      text = testScript;
      destination = "/test.py";
    };

    # The host-side glue is now thin: write manifest + test.py into
    # $TMPDIR, exec aos-test-driver, copy logs into $out. Per-machine
    # QEMU argv (including the mcast localaddr=127.0.0.1 pin) lives in
    # aos_test_driver/qemu.py.
    qemuDriverScript = ''
      set -eu

      # AOS build libs can conflict with QEMU's runtime linker.
      unset LD_LIBRARY_PATH

      cp ${manifestFile}/manifest.json "$TMPDIR/manifest.json"
      cp ${testPyFile}/test.py         "$TMPDIR/test.py"

      ${pkgs.aos-test-driver}/bin/aos-test-driver \
        --manifest "$TMPDIR/manifest.json" \
        --test     "$TMPDIR/test.py"

      mkdir -p "$out"
      for log in "$TMPDIR"/*-serial.log "$TMPDIR"/*-qemu.log; do
        [ -f "$log" ] && cp "$log" "$out/"
      done
      echo PASS > "$out/result"
    '';

    testDrv = pkgs.mkDerivation {
      pname = "aos-fleet-test-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.qemu
        pkgs.socat
        pkgs.python3
        pkgs.aos-test-driver
        # sgdisk — the driver relocates the GPT backup header after
        # growing an image-boot machine's per-run disk copy.
        pkgs.gptfdisk
      ];

      phases = [
        {
          name = "test";
          script = qemuDriverScript;
        }
      ];

      requiredSystemFeatures = ["kvm"];
    };
  in
    # Attach `driverInteractive` as a function on the test derivation —
    # mirrors nixpkgs' `passthru.driverInteractive` shape, but applied
    # directly so callers don't need to reach through `passthru`.
    # Build via:
    #   nix-build -E '((import ./. {}).checks.fleet.<suite>.driverInteractive) "ssh-..."'
    testDrv
    // {
      driverInteractive = sshAuthorizedKey:
        mkFleetTestInteractive {inherit spec sshAuthorizedKey;};
    };

  # ============================================================
  # mkFleetTestInteractive — outside-sandbox launcher.
  # ============================================================
  # Same kernel/initrd/disk closure as `mkFleetTest`, but the effective image
  # additionally bakes a root pubkey + DHCP on the user-mode NIC, and the
  # launcher script attaches a second
  # virtio-net NIC with `-netdev user,hostfwd=tcp:127.0.0.1:$PORT-:22`
  # so the host can reach each guest's sshd.
  #
  # Build product is `bin/run-fleet-interactive` — a tiny signal-reset
  # trampoline plus a self-contained shell payload with absolute store-path
  # references for bash, qemu, socat, and coreutils. Designed to run
  # **outside** the Nix sandbox; the aos CLI builds the derivation in-sandbox
  # and `exec`s the trampoline.
  #
  # No agent orchestration, no PING/SHUTDOWN. The user drives the VMs;
  # the launcher prints an SSH command table and `wait`s for SIGINT.
  mkFleetTestInteractive = {
    spec,
    sshAuthorizedKey,
  }: let
    inherit (spec) name machines;

    machinesWithIndex = mkMachinesWithIndex machines;
    hostsEntries = mkHostsEntries machinesWithIndex;
    machineBuilds = mkMachineBuilds {
      inherit machinesWithIndex hostsEntries sshAuthorizedKey;
    };

    # SSH host port = $AOS_FLEET_SSH_BASE + machine index, resolved at
    # launcher runtime (default 2222). Listening on 127.0.0.1 only. An
    # eval-time constant collided with whatever already holds :2222 on a
    # shared host; the env override keeps the launcher usable anywhere
    # without a rebuild.
    sshPort = mb: ''$(( AOS_FLEET_SSH_BASE + ${toString mb.index} ))'';

    # Per-machine launch fragment, spliced into the launcher.
    # Mirrors mkFleetTest's per-machine block, with two changes:
    #   - Adds a second `-netdev user,hostfwd=...` + `-device virtio-net-pci`
    #     for host→guest SSH on 127.0.0.1:$PORT.
    #   - Keeps the virtio-serial agent port and chardev. The host never
    #     connects to the agent socket in interactive mode, so the guest
    #     agent blocks indefinitely on read — quiet, no journal spam,
    #     no respawn loop. Removing the port would put the agent into
    #     "no transport found" → restart-on-failure every second.
    perMachineLaunch =
      lib.concatMapStringsSep "\n" (
        mb:
          if mb.bootMode == "image"
          then
            throw ''
              fleet '${name}': interactive mode does not support image-boot
              machines yet — drive the sandboxed test, or boot the image by
              hand per docs/boot/qemu-uefi.md.
            ''
          else ''
            echo ""
            echo "==> Starting machine: ${mb.name} (ip=${mb.ip} mac=${mb.mac} ssh-port=${toString (sshPort mb)})"

            AGENT_SOCK_${mb.name}="$FLEET_DIR/${mb.name}-agent.sock"
            SERIAL_SOCK_${mb.name}="$FLEET_DIR/${mb.name}-serial.sock"
            SERIAL_LOG_${mb.name}="$FLEET_DIR/${mb.name}-serial.log"
            QEMU_LOG_${mb.name}="$FLEET_DIR/${mb.name}-qemu.log"

            cp "${mb.disk}/disk.img" "$FLEET_DIR/${mb.name}-disk.img"
            chmod u+w "$FLEET_DIR/${mb.name}-disk.img"
            ${lib.optionalString (mb.metadataISO != null) ''
              cp "${mb.metadataISO}/metadata.iso" "$FLEET_DIR/${mb.name}-metadata.iso"
              chmod u+w "$FLEET_DIR/${mb.name}-metadata.iso"
            ''}

            VMLINUZ_${mb.name}=$(ls "${mb.kernel}/boot/vmlinuz-"* | head -1)
            INITRD_${mb.name}="${mb.initrd}/initrd.img"

            echo "  Kernel:   ''${VMLINUZ_${mb.name}}"
            echo "  Initrd:   ''${INITRD_${mb.name}}"
            echo "  Disk:     $FLEET_DIR/${mb.name}-disk.img"
            ${lib.optionalString (mb.metadataISO != null) ''
              echo "  Metadata: $FLEET_DIR/${mb.name}-metadata.iso"
            ''}

            "${pkgs.socat}/bin/socat" -u UNIX-LISTEN:"''${SERIAL_SOCK_${mb.name}}",reuseaddr,fork \
                                          OPEN:"''${SERIAL_LOG_${mb.name}}",creat,append &
            DRAIN_PIDS+=($!)
            SOCK_WAIT=0
            while [ ! -S "''${SERIAL_SOCK_${mb.name}}" ]; do
              sleep 0.05
              SOCK_WAIT=$((SOCK_WAIT + 1))
              if [ "$SOCK_WAIT" -gt 100 ]; then
                echo "ERROR: ${mb.name} serial drain socket did not appear within 5s" >&2
                exit 1
              fi
            done

            # The user-mode netdev (eth1) is added *after* the mcast netdev
            # (eth0) so PCI bus ordering puts the fleet NIC first under
            # `net.ifnames=0`. eth1 takes a DHCP lease from QEMU's built-in
            # 10.0.2.0/24 server; QEMU forwards 127.0.0.1:$PORT on the host
            # to :22 in the guest.
            "${pkgs.qemu}/bin/qemu-system-x86_64" \
              -machine q35,accel=kvm \
              -cpu host \
              -m ${toString mb.memoryMiB} \
              -smp 2 \
              -nographic \
              -kernel "''${VMLINUZ_${mb.name}}" \
              -initrd "''${INITRD_${mb.name}}" \
              -append "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 systemd.journald.forward_to_console=1 enforcing=0 net.ifnames=0" \
              -drive file="$FLEET_DIR/${mb.name}-disk.img",format=raw,if=virtio \
              ${lib.optionalString (mb.metadataISO != null) ''
              -drive id=metadata,file="$FLEET_DIR/${mb.name}-metadata.iso",if=none,format=raw,readonly=on \
              -device virtio-scsi-pci,id=scsi0 \
              -device scsi-cd,drive=metadata,bus=scsi0.0 \
            ''}
              -device virtio-serial \
              -device virtserialport,chardev=agent,name=aos.test.agent \
              -chardev socket,id=agent,path="''${AGENT_SOCK_${mb.name}}",server=on,wait=off \
              -chardev socket,id=ttyS0,path="''${SERIAL_SOCK_${mb.name}}",server=off \
              -serial chardev:ttyS0 \
              -netdev socket,id=fleet,mcast="$MCAST_GROUP:$MCAST_PORT",localaddr=127.0.0.1 \
              -device virtio-net-pci,netdev=fleet,mac=${mb.mac} \
              -netdev user,id=usernet,hostfwd=tcp:127.0.0.1:${toString (sshPort mb)}-:22 \
              -device virtio-net-pci,netdev=usernet,mac=${mb.debugMac} \
              -no-reboot \
                > "''${QEMU_LOG_${mb.name}}" 2>&1 &
            QEMU_PID_${mb.name}=$!
            QEMU_PIDS+=($!)
            sleep 0.2
            if ! kill -0 "''${QEMU_PID_${mb.name}}" 2>/dev/null; then
              echo "ERROR: QEMU for ${mb.name} exited immediately!" >&2
              cat "''${QEMU_LOG_${mb.name}}" 2>/dev/null || true
              exit 1
            fi
          ''
      )
      machineBuilds;

    sshTable =
      lib.concatMapStringsSep "\n" (mb: ''
        printf '    %-20s ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1\n' \
          '${mb.name}:' ${toString (sshPort mb)}
      '')
      machineBuilds;

    # Path-list of per-machine serial logs, for the post-launch tail-f hint.
    serialLogHints =
      lib.concatMapStringsSep "\n" (mb: ''
        printf '    %-20s tail -f %s\n' '${mb.name}:' "$FLEET_DIR/${mb.name}-serial.log"
      '')
      machineBuilds;

    launcherScript = ''
      #!${pkgs.bash}/bin/bash
      # Generated by lib/testing/fleet.nix (mkFleetTestInteractive).
      # Boots the '${name}' fleet outside the Nix sandbox with the embedded
      # SSH key authorised on root. Inter-VM L2 (192.168.50.0/24) is
      # preserved on eth0; an additional eth1 NIC carries QEMU user-mode
      # networking with TCP:22 forwarded to 127.0.0.1:<port>.
      #
      # The supplied SSH key is baked into each per-machine image;
      # to use a different key, rebuild the launcher with the new key.
      set -euo pipefail

      # AOS build libs can conflict with QEMU's runtime linker.
      unset LD_LIBRARY_PATH || true

      # Host port for the per-machine SSH forward: base + machine index.
      # Override when :2222 is taken on the host.
      AOS_FLEET_SSH_BASE="''${AOS_FLEET_SSH_BASE:-2222}"

      export PATH="${pkgs.coreutils}/bin:${pkgs.socat}/bin:${pkgs.qemu}/bin:''${PATH:-}"

      FLEET_DIR="''${TMPDIR:-/tmp}/aos-fleet-${name}-$$"
      mkdir -p "$FLEET_DIR"
      echo "Fleet runtime dir: $FLEET_DIR"

      # Per-launcher-process mcast endpoint for the inter-VM L2 segment.
      # Mirrors the PID-derived scheme in aos_test_driver/qemu.py so two
      # concurrent interactive fleets (or one alongside a sandboxed
      # `aos test fleet` run that escapes its netns) cannot cross-talk on
      # 230.0.0.1:1234 — the previous hardcoded group, which collided.
      # 239.0.0.0/8 is RFC 2365 organization-local scope; the last three
      # octets carry 24 bits of PID and the port adds a second axis.
      MCAST_GROUP="239.$(( ($$ >> 16) & 0xff )).$(( ($$ >> 8) & 0xff )).$(( $$ & 0xff ))"
      MCAST_PORT=$(( 10000 + ($$ % 50000) ))
      echo "Fleet L2 mcast: $MCAST_GROUP:$MCAST_PORT"

      if [ -e /dev/kvm ]; then
        echo "KVM: available"
      else
        echo "KVM: NOT available (the fleet will boot under TCG, expect very slow startup)"
      fi

      QEMU_PIDS=()
      DRAIN_PIDS=()
      _cleaned=0
      cleanup() {
        [ "$_cleaned" -eq 1 ] && return 0
        _cleaned=1
        echo ""
        echo "Shutting down fleet..."
        for pid in "''${QEMU_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
        for pid in "''${DRAIN_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
        wait 2>/dev/null || true
      }
      trap cleanup EXIT INT TERM

      ${perMachineLaunch}

      echo ""
      echo "==> Fleet '${name}' running outside the sandbox."
      echo ""
      echo "SSH backdoor (port-forwarded on 127.0.0.1):"
      ${sshTable}
      echo ""
      echo "Serial logs:"
      ${serialLogHints}
      echo ""
      echo "Press Ctrl-C to shut down."
      echo ""

      # Block until every QEMU exits. `wait <pids…>` is interruptible:
      # on SIGINT/SIGTERM bash returns immediately with status 128+signum
      # and *then* runs the trap, which kills the guests + drains and
      # waits for them. Control resumes past this `wait` once cleanup
      # has reaped them. On a natural exit (the user `poweroff`s every
      # guest from inside) `wait` returns 0 once every named PID is
      # gone. The earlier polling-loop variant deadlocked the cleanup
      # trap up to 1 s waiting for the foreground `sleep` to return —
      # `wait` interrupts cleanly without that delay.
      #
      # `|| true` is load-bearing: with set -e a 128+signum return from
      # the interrupted wait, or a 127 from waiting on an already-reaped
      # PID, would otherwise terminate the script before the banner.
      wait "''${QEMU_PIDS[@]}" || true

      echo "All QEMU instances have exited."
    '';

    # Background-job shells start children with SIGINT and SIGQUIT ignored.
    # Bash cannot install traps for signals inherited as SIG_IGN, so reset both
    # dispositions before Bash starts. Keeping this in the generated launcher
    # lets the Rust CLI remain `forbid(unsafe_code)` while retaining graceful
    # Ctrl-C shutdown in foreground and background invocations.
    launcherWrapperSource = ''
      #include <signal.h>
      #include <stdio.h>
      #include <unistd.h>

      int main(int argc, char **argv) {
        if (signal(SIGINT, SIG_DFL) == SIG_ERR ||
            signal(SIGQUIT, SIG_DFL) == SIG_ERR) {
          perror("run-fleet-interactive: reset signal disposition");
          return 126;
        }

        char *launcher_argv[argc + 2];
        launcher_argv[0] = "bash";
        launcher_argv[1] = LAUNCHER_SCRIPT;
        for (int index = 1; index < argc; ++index) {
          launcher_argv[index + 1] = argv[index];
        }
        launcher_argv[argc + 1] = NULL;

        execv("${pkgs.bash}/bin/bash", launcher_argv);
        perror("run-fleet-interactive: exec bash");
        return 127;
      }
    '';
  in
    pkgs.mkDerivation {
      pname = "aos-fleet-interactive-${name}";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      # The output is the launcher script, executed outside the sandbox
      # after the build; its embedded store paths (qemu, disks, kernels,
      # metadata ISOs) are the product. The default nuke-references scrub
      # would rewrite them to dummy hashes and the launcher would try to
      # copy from a non-existent dummy /nix/store path at runtime.
      dontNukeRefs = true;

      LAUNCHER_SCRIPT = launcherScript;
      LAUNCHER_WRAPPER_SOURCE = launcherWrapperSource;

      phases = [
        {
          name = "build";
          script = ''
            mkdir -p $out/bin $out/libexec
            printf '%s\n' "$LAUNCHER_SCRIPT" > $out/libexec/run-fleet-interactive.sh
            printf '%s\n' "$LAUNCHER_WRAPPER_SOURCE" > $TMPDIR/run-fleet-interactive.c
            cc -std=c99 -Wall -Wextra -Werror \
              -DLAUNCHER_SCRIPT="\"$out/libexec/run-fleet-interactive.sh\"" \
              $TMPDIR/run-fleet-interactive.c \
              -o $out/bin/run-fleet-interactive
          '';
        }
      ];
    };
in {
  inherit mkFleetTest mkFleetTestInteractive uriEncode dataUrl;
}

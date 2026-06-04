# lib/testing/fleet.nix — Multi-VM test orchestrator (QEMU-only).
#
# Each machine boots through the production initrd path (stage-1 systemd
# → ignition stages → switch-root → stage-2 systemd) with an aos-metadata
# ISO9660 disk attached. Per-machine identity (hostname, /etc/hosts,
# eth0 .network) ships in that ISO as ignition `storage.files` — the
# rootfs disk is identical across every machine of a given system variant.
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
#                                       and an SSH-key fragment delivered
#                                       through ignition. Reachable via
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
  metadataLib = import ./metadata.nix {inherit pkgs lib;};

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

  # ── Minimal URI encoder for ignition `data:` URLs ──────────────────
  # builtins.replaceStrings scans the input and emits replacements
  # without rescanning the output, so listing `%` first is safe — the
  # `%` we emit when escaping `\n` (→ `%0A`) does NOT trigger another
  # round of escaping. Covers every reserved char that arises in the
  # content we synthesise here (hostnames, /etc/hosts, systemd unit
  # bodies including `[Section]` headers, ssh authorized_keys lines);
  # callers needing more should add to the lists in lockstep.
  uriEncode =
    builtins.replaceStrings
    ["%" "\n" "#" "?" " " "&" "+" "=" "[" "]"]
    ["%25" "%0A" "%23" "%3F" "%20" "%26" "%2B" "%3D" "%5B" "%5D"];
  dataUrl = content: "data:,${uriEncode content}";

  # ── Per-machine derivation order ───────────────────────────────────
  # Drives IP, MAC, banner ordering. `lib.imap` is the AOS lib's
  # 0-indexed iterator (lib/lists.nix:97). `debugMac` is allocated
  # whether or not interactive mode is enabled — it's cheap (string
  # interpolation only) and keeping it as a stable per-machine field
  # avoids parameterising downstream helpers on the mode.
  mkMachinesWithIndex = machines: let
    machineNames = builtins.attrNames machines;
  in
    lib.imap (i: mname: let
      m = machines.${mname};
    in {
      inherit (m) system roles instanceMetadata;
      # `extraClosures` defaults to [] on the fleet machine type, so this
      # `or []` only matters for callers bypassing fleet-spec validation.
      extraClosures = m.extraClosures or [];
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

  # ── Per-machine identity fragment (ignition) ───────────────────────
  # Hostname, /etc/hosts, and the eth0 .network file. In production,
  # the platform delivers equivalent fragments via cloud-init
  # userdata or IPMI virtual media. Here the harness synthesises them
  # from the fleet topology.
  #
  # The .network matches by `MACAddress=` (not `Name=eth0`) so the
  # binding is robust against future changes in interface naming. With
  # `net.ifnames=0` already in the kernel cmdline, the primary mcast
  # virtio-net NIC is `eth0` deterministically — but matching by MAC
  # is the level at which the policy actually wants to live.
  mkFleetIdentityFragment = hostsEntries: m: {
    storage.files = [
      {
        path = "/etc/hostname";
        mode = 420; # 0644
        overwrite = true;
        contents.source = dataUrl "${m.name}\n";
      }
      {
        path = "/etc/hosts";
        mode = 420;
        overwrite = true;
        contents.source = dataUrl ''
          127.0.0.1 localhost
          ${hostsEntries}
        '';
      }
      {
        path = "/etc/systemd/network/10-fleet-eth0.network";
        mode = 420;
        overwrite = true;
        contents.source = dataUrl ''
          [Match]
          MACAddress=${m.mac}

          [Network]
          Address=${m.ip}/24
        '';
      }
    ];
  };

  # ── Debug fragment for interactive mode ────────────────────────────
  # Two files, only present when `mkFleetTestInteractive` is used:
  #   - /etc/ssh/authorized_keys/root  — root pubkey, mode 0600. The
  #     authorizedKeysFile default in modules/security/ssh.nix is
  #     "/etc/ssh/authorized_keys/%u", so root login uses this exact
  #     path. Ignition auto-creates the parent directory; the existing
  #     tmpfiles rule (modules/security/ssh.nix:469) is idempotent
  #     when it runs at stage-2.
  #   - /etc/systemd/network/20-debug-eth1.network — DHCP on the
  #     user-mode NIC the launcher attaches alongside the fleet's
  #     primary mcast NIC. Matches by MAC for symmetry with the
  #     fleet identity fragment.
  mkDebugFragment = sshAuthorizedKey: m: {
    storage.files = [
      {
        path = "/etc/ssh/authorized_keys/root";
        mode = 384; # 0600
        overwrite = true;
        contents.source = dataUrl "${sshAuthorizedKey}\n";
      }
      {
        path = "/etc/systemd/network/20-debug-eth1.network";
        mode = 420;
        overwrite = true;
        contents.source = dataUrl ''
          [Match]
          MACAddress=${m.debugMac}

          [Network]
          DHCP=ipv4
        '';
      }
    ];
  };

  # ── Compose final ignition for one machine ──────────────────────────
  # Identity fragment is always present; the optional debug fragment is
  # layered between identity and user/role merges; user-supplied
  # `instanceMetadata` then layers on top. Identity files use stable
  # paths (`/etc/hostname`, `/etc/hosts`,
  # `/etc/systemd/network/10-fleet-eth0.network`); the debug fragment
  # adds two more (`/etc/ssh/authorized_keys/root`,
  # `/etc/systemd/network/20-debug-eth1.network`). A user fragment
  # writing to any of those produces a duplicate-`path` error at
  # ignition-validate time. We catch it earlier — at evalModules time
  # — with a useful message naming the offending paths.
  composeIgnition = {
    name,
    identity,
    debug ? null,
  }: m: let
    mIdentity = identity m;
    mDebug =
      if debug != null
      then debug m
      else {storage.files = [];};

    identityPaths = builtins.map (f: f.path) mIdentity.storage.files;
    debugPaths = builtins.map (f: f.path) mDebug.storage.files;
    reservedPaths = identityPaths ++ debugPaths;

    roleMerges =
      builtins.map
      (r: {source = "file:///etc/aos/ignition-roles/${r}";})
      m.roles;
    userCfg =
      if m.instanceMetadata != null
      then m.instanceMetadata.config
      else {};

    # `storage` is `nullOr submodule` (lib/formats/ignition.nix:392)
    # with default null — `userCfg.storage` exists but may BE null,
    # so a literal `userCfg.storage or {}` would not catch it
    # (`or` only catches missing-attr errors). Unwrap explicitly.
    # `ignition` is a non-null submodule (default `{}`), so the same
    # treatment isn't needed for the merge path.
    maybeNull = x: default:
      if x == null
      then default
      else x;
    userStorage = maybeNull (userCfg.storage or null) {};

    userMerges = ((userCfg.ignition or {}).config or {}).merge or [];
    userFiles = userStorage.files or [];

    collisions =
      builtins.filter
      (f: builtins.elem f.path reservedPaths)
      userFiles;
  in
    if collisions != []
    then
      throw ''
        fleet '${name}': machine "${m.name}" instanceMetadata.config.storage.files
        collides with reserved path(s):
          ${lib.concatStringsSep ", " (builtins.map (f: f.path) collisions)}
        Reserved paths: ${lib.concatStringsSep ", " reservedPaths}.
        Pick a different path, or move the override into a role.
      ''
    else
      userCfg
      // {
        # `merge` is reconstructed as `roleMerges ++ userMerges` — both
        # contribute, role merges first. The collision check above only
        # inspects `storage.files`; merge entries aren't path-scoped and
        # are safe to concatenate.
        ignition =
          (userCfg.ignition or {})
          // {
            config =
              ((userCfg.ignition or {}).config or {})
              // {
                merge = roleMerges ++ userMerges;
              };
          };
        storage =
          userStorage
          // {
            files =
              mIdentity.storage.files
              ++ mDebug.storage.files
              ++ userFiles;
          };
      };

  # ── Per-machine builds ─────────────────────────────────────────────
  # `disk` is a function of `{system, extraClosures}` — Nix dedups
  # identical derivations, so two machines with the same system and the
  # same extraClosures reference one disk (machines differing only by
  # extraClosures get distinct disks).
  # `metadataISO` is the only per-machine derivation; in interactive
  # mode the SSH-key+DHCP fragment changes the ignition input, so
  # interactive ISOs hash differently from sandboxed-test ISOs.
  mkMachineBuilds = {
    name,
    machinesWithIndex,
    identity,
    debug ? null,
  }:
    builtins.map (m: {
      inherit (m) name ip mac debugMac index system roles;
      kernel = m.system.config.system.build.kernel;
      initrd = m.system.config.system.build.initrd;
      disk = vmLib.mkTestDisk {
        system = m.system;
        inherit (m) extraClosures;
      };
      metadataISO = metadataLib.mkMetadataIso {
        name = "${name}-${m.name}";
        ignitionConfig = composeIgnition {inherit name identity debug;} m;
      };
    })
    machinesWithIndex;

  # ============================================================
  # mkFleetTest — sandboxed test launcher (the original entry point).
  # ============================================================
  mkFleetTest = spec: let
    # spec is already validated against fleetSpecType by the discoverer
    # — including the per-machine `roles` enum-against-`config.aos.roles`.
    inherit (spec) name testScript timeout machines;

    machinesWithIndex = mkMachinesWithIndex machines;
    hostsEntries = mkHostsEntries machinesWithIndex;
    identity = mkFleetIdentityFragment hostsEntries;
    machineBuilds = mkMachineBuilds {inherit name machinesWithIndex identity;};

    # Driver manifest. One entry per fleet machine; transport pinned to
    # qemu. The driver consumes this JSON and starts each VM in order,
    # then exposes each machine to the testScript as a Python global
    # named after `mb.name` (e.g. controlplane, worker). v1 fleet QEMU
    # uniformly uses 2 GiB / 2 vCPU per machine — matching the previous
    # hardcoded `-m 2048 -smp 2`.
    manifest = {
      inherit name timeout;
      machines =
        builtins.map (mb: {
          inherit (mb) name mac ip;
          transport = "qemu";
          kernel = builtins.toString mb.kernel;
          initrd = "${builtins.toString mb.initrd}/initrd.img";
          disk = "${builtins.toString mb.disk}/disk.img";
          metadata = "${builtins.toString mb.metadataISO}/metadata.iso";
          memory_mib = 8192;
          vcpu_count = 2;
        })
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
  # Same kernel/initrd/disk closure as `mkFleetTest`, but the metadata
  # ISO carries an additional ignition fragment (root pubkey + DHCP on
  # the user-mode NIC), and the launcher script attaches a second
  # virtio-net NIC with `-netdev user,hostfwd=tcp:127.0.0.1:$PORT-:22`
  # so the host can reach each guest's sshd.
  #
  # Build product is `bin/run-fleet-interactive` — a self-contained
  # shell script with absolute store-path references for qemu, socat,
  # coreutils. Designed to run **outside** the Nix sandbox; the aos
  # CLI builds the derivation in-sandbox and `exec`s the script.
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
    identity = mkFleetIdentityFragment hostsEntries;
    debug = mkDebugFragment sshAuthorizedKey;
    machineBuilds = mkMachineBuilds {
      inherit name machinesWithIndex identity debug;
    };

    # SSH host port = 2222 + machine index. Listening on 127.0.0.1 only.
    sshPort = mb: 2222 + mb.index;

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
      lib.concatMapStringsSep "\n" (mb: ''
        echo ""
        echo "==> Starting machine: ${mb.name} (ip=${mb.ip} mac=${mb.mac} ssh-port=${toString (sshPort mb)})"

        AGENT_SOCK_${mb.name}="$FLEET_DIR/${mb.name}-agent.sock"
        SERIAL_SOCK_${mb.name}="$FLEET_DIR/${mb.name}-serial.sock"
        SERIAL_LOG_${mb.name}="$FLEET_DIR/${mb.name}-serial.log"
        QEMU_LOG_${mb.name}="$FLEET_DIR/${mb.name}-qemu.log"

        cp "${mb.disk}/disk.img" "$FLEET_DIR/${mb.name}-disk.img"
        chmod u+w "$FLEET_DIR/${mb.name}-disk.img"
        cp "${mb.metadataISO}/metadata.iso" "$FLEET_DIR/${mb.name}-metadata.iso"
        chmod u+w "$FLEET_DIR/${mb.name}-metadata.iso"

        VMLINUZ_${mb.name}=$(ls "${mb.kernel}/boot/vmlinuz-"* | head -1)
        INITRD_${mb.name}="${mb.initrd}/initrd.img"

        echo "  Kernel:   ''${VMLINUZ_${mb.name}}"
        echo "  Initrd:   ''${INITRD_${mb.name}}"
        echo "  Disk:     $FLEET_DIR/${mb.name}-disk.img"
        echo "  Metadata: $FLEET_DIR/${mb.name}-metadata.iso"

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
          -m 8192 \
          -smp 2 \
          -nographic \
          -kernel "''${VMLINUZ_${mb.name}}" \
          -initrd "''${INITRD_${mb.name}}" \
          -append "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 systemd.journald.forward_to_console=1 enforcing=0 net.ifnames=0" \
          -drive file="$FLEET_DIR/${mb.name}-disk.img",format=raw,if=virtio \
          -drive id=metadata,file="$FLEET_DIR/${mb.name}-metadata.iso",if=none,format=raw,readonly=on \
          -device virtio-scsi-pci,id=scsi0 \
          -device scsi-cd,drive=metadata,bus=scsi0.0 \
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
      '')
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
      # The supplied SSH key is baked into each per-machine metadata ISO;
      # to use a different key, rebuild the launcher with the new key.
      set -euo pipefail

      # AOS build libs can conflict with QEMU's runtime linker.
      unset LD_LIBRARY_PATH || true

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
  in
    pkgs.mkDerivation {
      pname = "aos-fleet-interactive-${name}";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      LAUNCHER_SCRIPT = launcherScript;

      phases = [
        {
          name = "build";
          script = ''
            mkdir -p $out/bin
            printf '%s\n' "$LAUNCHER_SCRIPT" > $out/bin/run-fleet-interactive
            chmod +x $out/bin/run-fleet-interactive
          '';
        }
      ];
    };
in {
  inherit mkFleetTest mkFleetTestInteractive;
}

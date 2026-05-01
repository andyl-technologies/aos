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
{
  pkgs,
  lib,
}: let
  vmLib = import ./vm.nix {inherit pkgs lib;};
  metadataLib = import ./metadata.nix {inherit pkgs lib;};
  assertions = import ./assertions.nix {inherit (pkgs) aos-agent-rpc;};

  # ── MAC scheme (mirrors NixOS qemu-common.nix) ─────────────────────
  # 52:54:00:12:<vlan>:<machine>. Vlan stays 0 in this revision; the
  # encoding leaves room for a second L2 segment without resyncing
  # callers. Two-hex-digit padding keeps the resulting string well-formed
  # for both single- and double-digit numbers.
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
  # bodies including `[Section]` headers); callers needing more
  # should add to the lists in lockstep.
  uriEncode =
    builtins.replaceStrings
    ["%" "\n" "#" "?" " " "&" "+" "=" "[" "]"]
    ["%25" "%0A" "%23" "%3F" "%20" "%26" "%2B" "%3D" "%5B" "%5D"];
  dataUrl = content: "data:,${uriEncode content}";

  mkFleetTest = spec: let
    # spec is already validated against fleetSpecType by the discoverer
    # — including the per-machine `roles` enum-against-`config.aos.roles`.
    inherit (spec) name testScript timeout machines;
    machineNames = builtins.attrNames machines;

    # Per-machine derivation order — drives IP, MAC, banner ordering.
    # `lib.imap` is the AOS lib's 0-indexed iterator (lib/lists.nix:97).
    machinesWithIndex =
      lib.imap (i: mname: let
        m = machines.${mname};
      in {
        inherit (m) system roles instanceMetadata;
        name = mname;
        ip = "192.168.50.${toString (i + 10)}";
        mac = mkMac 0 (i + 1);
        index = i;
      })
      machineNames;

    # /etc/hosts entries seen by every machine — every guest sees every
    # other guest by name. Test scripts use this implicitly
    # (curl http://server:8000/).
    hostsEntries =
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
    # `net.ifnames=0` already in the kernel cmdline, the single virtio-net
    # NIC is `eth0` deterministically — but matching by MAC is the level
    # at which the policy actually wants to live.
    fleetIdentityFragment = m: {
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

    # ── Compose final ignition for one machine ──────────────────────────
    # Identity fragment is always present; role merges and user-supplied
    # `instanceMetadata` are layered on top. Identity files use stable
    # paths (`/etc/hostname`, `/etc/hosts`,
    # `/etc/systemd/network/10-fleet-eth0.network`), so a user fragment
    # that writes to any of those would produce a duplicate-`path` error
    # at ignition-validate time. We catch it earlier — at evalModules
    # time — with a useful message naming the offending paths.
    composeIgnition = m: let
      identity = fleetIdentityFragment m;
      identityPaths = builtins.map (f: f.path) identity.storage.files;
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
        (f: builtins.elem f.path identityPaths)
        userFiles;
    in
      if collisions != []
      then
        throw ''
          mkFleetTest '${name}': machine "${m.name}" instanceMetadata.config.storage.files
          collides with the fleet identity fragment at path(s):
            ${lib.concatStringsSep ", " (builtins.map (f: f.path) collisions)}
          The identity fragment owns: ${lib.concatStringsSep ", " identityPaths}.
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
              files = identity.storage.files ++ userFiles;
            };
        };

    # ── Per-machine builds ─────────────────────────────────────────────
    # `disk` is a function of `system` only — Nix dedups identical
    # derivations, so two machines on the same system reference one disk.
    # `metadataISO` is the only per-machine derivation.
    machineBuilds =
      builtins.map (m: {
        inherit (m) name ip mac index system roles;
        kernel = m.system.config.system.build.kernel;
        initrd = m.system.config.system.build.initrd;
        disk = vmLib.mkTestDisk {system = m.system;};
        metadataISO = metadataLib.mkMetadataIso {
          name = "${name}-${m.name}";
          ignitionConfig = composeIgnition m;
        };
      })
      machinesWithIndex;

    # ============================================================
    # Shell template
    # ============================================================
    # The script splices a per-machine block for launch, agent-wait, and
    # shutdown. Per-machine shell variables follow the convention
    # AGENT_SOCK_<name> / SERIAL_SOCK_<name> / SERIAL_LOG_<name> /
    # QEMU_LOG_<name> / VMLINUZ_<name> / INITRD_<name> / QEMU_PID_<name>;
    # the first one is required by assertions.fleetHelpers (§8).
    qemuScript = ''
      set -euo pipefail

      FLEET_DIR="$TMPDIR/fleet"
      mkdir -p "$FLEET_DIR"

      # AOS build libs can conflict with QEMU's runtime linker.
      unset LD_LIBRARY_PATH

      # PID tracking: separate arrays for QEMU and serial-drain processes.
      # cleanup() walks both. The trap fires on any exit (success or
      # failure); the happy path also drains explicitly before reaching it.
      QEMU_PIDS=()
      DRAIN_PIDS=()
      cleanup() {
        for pid in "''${QEMU_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
        for pid in "''${DRAIN_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
        wait 2>/dev/null || true
      }
      trap cleanup EXIT

      qemu-system-x86_64 --version >/dev/null \
        || { echo "ERROR: qemu-system-x86_64 missing or non-functional"; exit 1; }

      # ============================================================
      # Per-machine launch
      # ============================================================
      ${lib.concatMapStringsSep "\n" (mb: ''
          echo ""
          echo "==> Starting machine: ${mb.name} (ip=${mb.ip} mac=${mb.mac})"

          AGENT_SOCK_${mb.name}="$FLEET_DIR/${mb.name}-agent.sock"
          SERIAL_SOCK_${mb.name}="$FLEET_DIR/${mb.name}-serial.sock"
          SERIAL_LOG_${mb.name}="$FLEET_DIR/${mb.name}-serial.log"
          QEMU_LOG_${mb.name}="$FLEET_DIR/${mb.name}-qemu.log"

          # Per-machine writable copy. The disk is shared across machines of
          # this system variant (Nix dedups), but each VM needs a writable
          # copy because qemu opens it rw. The metadata ISO is per-machine
          # already; the local copy isolates the run from any read-side
          # caching quirks with store files on certain filesystems.
          cp "${mb.disk}/disk.img" "$FLEET_DIR/${mb.name}-disk.img"
          chmod u+w "$FLEET_DIR/${mb.name}-disk.img"
          cp "${mb.metadataISO}/metadata.iso" "$FLEET_DIR/${mb.name}-metadata.iso"
          chmod u+w "$FLEET_DIR/${mb.name}-metadata.iso"

          VMLINUZ_${mb.name}=$(ls "${mb.kernel}/boot/vmlinuz-"* | head -1)
          INITRD_${mb.name}="${mb.initrd}/initrd.img"

          # Preflight banner — failure to find vmlinuz/initrd surfaces here
          # as a diagnostic, not as a cryptic qemu error 100ms later.
          echo "  Driver:   qemu (fleet)"
          echo "  Kernel:   ''${VMLINUZ_${mb.name}}"
          echo "  Initrd:   ''${INITRD_${mb.name}}"
          echo "  Disk:     $FLEET_DIR/${mb.name}-disk.img ($(ls -lh "$FLEET_DIR/${mb.name}-disk.img" | awk '{print $5}'))"
          echo "  Metadata: $FLEET_DIR/${mb.name}-metadata.iso ($(ls -lh "$FLEET_DIR/${mb.name}-metadata.iso" | awk '{print $5}'))"
          if [ -e /dev/kvm ]; then echo "  KVM: available"; else echo "  KVM: NOT available"; fi

          # Serial drain — unidirectional listener appending to ${mb.name}-serial.log.
          # Must be up before QEMU connects; the wait loop guards against early-
          # boot output being lost. -u + OPEN-with-creat,append matches vm.nix.
          socat -u UNIX-LISTEN:"''${SERIAL_SOCK_${mb.name}}",reuseaddr,fork \
                   OPEN:"''${SERIAL_LOG_${mb.name}}",creat,append &
          DRAIN_PIDS+=($!)
          SOCK_WAIT=0
          while [ ! -S "''${SERIAL_SOCK_${mb.name}}" ]; do
            sleep 0.05
            SOCK_WAIT=$((SOCK_WAIT + 1))
            if [ "$SOCK_WAIT" -gt 100 ]; then
              echo "ERROR: ${mb.name} serial drain socket did not appear within 5s"
              exit 1
            fi
          done

          # QEMU launch. The metadata ISO rides on a SCSI CD-ROM so the guest
          # sees /dev/sr0 with ISO9660 volume label `aos-metadata` —
          # exactly what aos-platform-detect.service probes for.
          # `localaddr=127.0.0.1` on the mcast netdev binds the multicast
          # socket to loopback. Without it QEMU asks the kernel to pick
          # an outbound interface for 230.0.0.1, and the Nix sandbox's
          # network namespace has only `lo` — which doesn't carry the
          # IFF_MULTICAST flag — so the kernel rejects IP_ADD_MEMBERSHIP
          # with "No such device". Pinning to 127.0.0.1 routes the
          # mcast traffic through lo explicitly and works around the
          # missing flag (no CAP_NET_ADMIN required to set it). Cross-
          # process delivery between QEMU instances on the same host
          # works as designed.
          qemu-system-x86_64 \
            -machine q35,accel=kvm \
            -cpu host \
            -m 2048 \
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
            -netdev socket,id=net0,mcast=230.0.0.1:1234,localaddr=127.0.0.1 \
            -device virtio-net-pci,netdev=net0,mac=${mb.mac} \
            -no-reboot \
              > "''${QEMU_LOG_${mb.name}}" 2>&1 &
          QEMU_PID_${mb.name}=$!
          QEMU_PIDS+=($!)
          sleep 0.2
          if ! kill -0 "''${QEMU_PID_${mb.name}}" 2>/dev/null; then
            echo "ERROR: QEMU for ${mb.name} exited immediately!"
            echo "--- ${mb.name} qemu log ---"
            cat "''${QEMU_LOG_${mb.name}}" 2>/dev/null || true
            exit 1
          fi
        '')
        machineBuilds}

      # ============================================================
      # Wait for every guest agent (PING/PONG via virtio-serial).
      # ============================================================
      # The kill -0 inside the loop is the load-bearing detail: if any QEMU
      # exits during agent-wait, dump that machine's logs *now* and fail
      # with context — not after the deadline fires with empty logs.
      START_TIME=$(date +%s)
      DEADLINE=$((START_TIME + ${toString timeout}))

      ${assertions.fleetHelpers}

      ${lib.concatMapStringsSep "\n" (mb: ''
          echo "Waiting for ${mb.name} agent..."
          AGENT_READY_${mb.name}=0
          while [ "$(date +%s)" -lt "$DEADLINE" ]; do
            if ! kill -0 "''${QEMU_PID_${mb.name}}" 2>/dev/null; then
              echo "ERROR: ${mb.name} (qemu) exited while waiting for its agent"
              echo "--- ${mb.name} qemu log ---"
              cat "''${QEMU_LOG_${mb.name}}" 2>/dev/null || true
              echo "--- ${mb.name} serial log ---"
              cat "''${SERIAL_LOG_${mb.name}}" 2>/dev/null || true
              exit 1
            fi
            if [ -S "''${AGENT_SOCK_${mb.name}}" ]; then
              RESPONSE=$(${assertions.rpcBin} --driver qemu "''${AGENT_SOCK_${mb.name}}" "PING" 2>/dev/null || true)
              if echo "$RESPONSE" | grep -q '"ready"'; then
                echo "${mb.name} agent ready."
                AGENT_READY_${mb.name}=1
                break
              fi
            fi
            sleep 0.5
          done
          if [ "''${AGENT_READY_${mb.name}}" -ne 1 ]; then
            echo "TIMEOUT: ${mb.name} agent did not become ready within ${toString timeout}s"
            echo "--- ${mb.name} serial log ---"
            cat "''${SERIAL_LOG_${mb.name}}" 2>/dev/null || true
            echo "--- ${mb.name} qemu log ---"
            cat "''${QEMU_LOG_${mb.name}}" 2>/dev/null || true
            exit 1
          fi
        '')
        machineBuilds}

      # ============================================================
      # Run the test script
      # ============================================================
      echo ""
      echo "==> Running fleet test: ${name}"
      echo ""

      ${testScript}

      # ============================================================
      # Shutdown — happy path; the cleanup trap covers failure paths.
      # ============================================================
      echo ""
      echo "Shutting down fleet..."
      ${lib.concatMapStringsSep "\n" (mb: ''
          ${assertions.rpcBin} --driver qemu "''${AGENT_SOCK_${mb.name}}" "SHUTDOWN" 2>/dev/null || true
        '')
        machineBuilds}
      sleep 2
      for pid in "''${QEMU_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
      for pid in "''${DRAIN_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
      wait 2>/dev/null || true
      trap - EXIT

      # ============================================================
      # Result
      # ============================================================
      echo ""
      echo "==> Fleet test passed: ${name}"
      mkdir -p "$out"
      echo "PASS" > "$out/result"
      ${lib.concatMapStringsSep "\n" (mb: ''
          cp "''${SERIAL_LOG_${mb.name}}" "$out/${mb.name}-serial.log" 2>/dev/null || true
          cp "''${QEMU_LOG_${mb.name}}"   "$out/${mb.name}-qemu.log"   2>/dev/null || true
        '')
        machineBuilds}
    '';
  in
    pkgs.mkDerivation {
      pname = "aos-fleet-test-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.socat
        pkgs.jq
        pkgs.qemu
        pkgs.aos-agent-rpc
      ];

      phases = [
        {
          name = "test";
          script = qemuScript;
        }
      ];

      requiredSystemFeatures = ["kvm"];
    };
in {
  inherit mkFleetTest;
}

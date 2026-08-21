##! crucible-fixtures — minimal RFC-0010 guest root-image fixtures
{
  lib,
  stdenv,
  mkDerivation,
  bash,
  coreutils,
  e2fsprogs,
  fakeroot,
  util-linux,
  crucible-guest,
  openssh,
}: let
  version = "0.1.0";
  fixtureName = "aos-minimal";
  thirdPartyGuestName = "generic-aos-linux-unmodified";
  rootImageRelativePath = "share/crucible/fixtures/root/${fixtureName}-root.ext4";
  thirdPartyRootImageRelativePath = "share/crucible/fixtures/third-party-guests/${thirdPartyGuestName}/root.ext4";
  thirdPartyGuestPath = "share/crucible/fixtures/third-party-guests/${thirdPartyGuestName}/manifest.toml";
  entropySeedFileName = "crucible-guest-entropy-seed.bin";
  entropySeedRelativePath = "share/crucible/fixtures/entropy/${entropySeedFileName}";
  hostStoreMountTag = "crucible-store";
  ext4FeatureFlags = "^has_journal,^metadata_csum,^64bit";
  entropySeedMechanism = "scenario-seed-fw_cfg-plus-seeded-qemu-rng";
  fixtureConsole =
    {
      "x86_64-linux" = "ttyS0";
      "aarch64-linux" = "ttyAMA0";
    }
    .${
      stdenv.hostPlatform.system
    }
    or (throw "crucible-fixtures: unsupported system '${stdenv.hostPlatform.system}'");

  fixtureClosureDeps = [
    bash
    coreutils
    util-linux
    crucible-guest
    openssh
  ];
  thirdPartyClosureDeps = [
    bash
    coreutils
    util-linux
  ];

  graphFor = prefix: deps:
    lib.concatLists
    (lib.imap (i: dep: [
        "${prefix}-${builtins.toString i}"
        dep
      ])
      deps);
  graphPairs =
    graphFor "fixture-closure" fixtureClosureDeps
    ++ graphFor "third-party-closure" thirdPartyClosureDeps;

  pathFor = deps:
    lib.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in [
          "${base}/bin"
          "${base}/sbin"
        ]
      )
      deps
    );
  fixtureBootPath = pathFor fixtureClosureDeps;
  thirdPartyBootPath = pathFor thirdPartyClosureDeps;

  fixtureNodes = [
    {
      name = fixtureName;
      contentAddressedNodeId = "build-output-root-image-sha256";
      macAddress = "build-output-derived";
      macDerivation = "sha256(root-image-sha256)";
    }
    {
      name = thirdPartyGuestName;
      contentAddressedNodeId = "build-output-root-image-sha256";
      macAddress = "build-output-derived";
      macDerivation = "sha256(root-image-sha256)";
    }
  ];

  qemuLaunchFragment = ''
    -kernel $CRUCIBLE_KERNEL
    -append "$CRUCIBLE_KERNEL_CMDLINE root=/dev/vda init=/init console=${fixtureConsole}"
    -drive id=crucible-root,file=$COW_OVERLAY,format=qcow2,if=none,cache=unsafe,discard=unmap
    -device virtio-blk-pci,drive=crucible-root,id=crucible-root0
    -fsdev local,id=crucible-store,path=/nix/store,security_model=none,readonly=on
    -device virtio-9p-pci,fsdev=crucible-store,mount_tag=${hostStoreMountTag}
    -fw_cfg name=opt/crucible/seed,file=${entropySeedFileName}
  '';
  cowOverlayScript = ''
    #!${bash}/bin/bash
    set -euo pipefail

    : "''${QEMU_IMG:?QEMU_IMG must point to qemu-img}"
    : "''${BASE_IMAGE:?BASE_IMAGE must point to the read-only base image}"
    : "''${COW_OVERLAY:?COW_OVERLAY must name the writable qcow2 overlay}"

    if [ -w "$BASE_IMAGE" ]; then
      echo "BASE_IMAGE must be read-only before creating a Crucible CoW overlay" >&2
      exit 1
    fi

    exec "$QEMU_IMG" create -f qcow2 -F raw -b "$BASE_IMAGE" "$COW_OVERLAY"
  '';
in
  mkDerivation {
    pname = "crucible-fixtures";
    inherit version;
    src = null;

    buildDeps = [
      coreutils
      e2fsprogs
      fakeroot
      util-linux
    ];
    runtimeDeps = [];

    exportReferencesGraph = graphPairs;

    # The filesystem images deliberately contain store paths and binaries.
    # Rewriting references after mkfs would corrupt the image bytes.
    dontNukeRefs = true;

    passthru = {
      crucibleFixtureRootImage = rootImageRelativePath;
      crucibleFixtureExt4Features = ext4FeatureFlags;
      crucibleFixtureReadOnlyBase = true;
      crucibleFixtureVirtio9pStoreShare = true;
      crucibleFixtureCopyOnWriteBoot = true;
      crucibleFixtureEntropySeedMechanism = entropySeedMechanism;
      crucibleFixtureEntropySeedFileName = entropySeedFileName;
      crucibleFixtureConsole = fixtureConsole;
      crucibleFixtureNodes = fixtureNodes;
      crucibleFixtureThirdPartyGuestPath = thirdPartyGuestPath;
      crucibleFixtureQemuLaunchFragment = qemuLaunchFragment;
    };

    phases = [
      {
        name = "build-fixtures";
        script = ''
          set -eu

          copy_closure() {
            prefix="$1"
            destination="$2"
            grep -h '^/nix/store/' "$prefix"-* | sort -u > "$prefix-paths"
            while IFS= read -r path; do
              target="$destination$path"
              mkdir -p "$(dirname "$target")"
              cp -a "$path" "$target"
            done < "$prefix-paths"
          }

          make_image() {
            source_dir="$1"
            label="$2"
            image="$3"
            apparent_kb=$(du -sk --apparent-size "$source_dir" | cut -f1)
            apparent_mib=$(( (apparent_kb + 1023) / 1024 ))
            image_mib=$(( apparent_mib * 3 / 2 + 64 ))
            if [ "$image_mib" -lt 128 ]; then
              image_mib=128
            fi
            fakeroot -- mkfs.ext4 -d "$source_dir" -L "$label" -m 0 -q \
              -O ${ext4FeatureFlags} \
              "$image" "''${image_mib}M"
            chmod 0444 "$image"
          }

          image_sha256() {
            set -- $(sha256sum "$1")
            printf '%s\n' "$1"
          }

          mac_from_hash() {
            hash="$1"
            o1=$(printf '%s' "$hash" | cut -c1-2)
            o2=$(printf '%s' "$hash" | cut -c3-4)
            o3=$(printf '%s' "$hash" | cut -c5-6)
            o4=$(printf '%s' "$hash" | cut -c7-8)
            o5=$(printf '%s' "$hash" | cut -c9-10)
            printf '02:%s:%s:%s:%s:%s\n' "$o1" "$o2" "$o3" "$o4" "$o5"
          }

          mkdir -p rootfs/bin rootfs/dev rootfs/etc rootfs/mnt/host-store
          mkdir -p rootfs/nix/store rootfs/proc rootfs/root rootfs/run rootfs/sys rootfs/tmp
          mkdir -p rootfs/sbin rootfs/var/empty rootfs/var/tmp rootfs/usr/bin rootfs/usr/sbin

          copy_closure fixture-closure rootfs

          ln -sfn ${bash}/bin/bash rootfs/bin/sh
          ln -sfn ${bash}/bin/bash rootfs/bin/bash
          ln -sfn ${coreutils}/bin/cat rootfs/bin/cat
          ln -sfn ${coreutils}/bin/echo rootfs/bin/echo
          ln -sfn ${coreutils}/bin/true rootfs/bin/true
          ln -sfn ${coreutils}/bin/uname rootfs/bin/uname

          cat > rootfs/etc/passwd <<'PASSWD'
          root:x:0:0:root:/root:/bin/sh
          sshd:x:74:74:Privilege-separated SSH:/var/empty:/bin/false
          PASSWD
          cat > rootfs/etc/group <<'GROUP'
          root:x:0:
          sshd:x:74:
          GROUP
          cat > rootfs/etc/shadow <<'SHADOW'
          root::1:0:99999:7:::
          sshd:!:1:0:99999:7:::
          SHADOW
          chmod 0600 rootfs/etc/shadow

          cat > rootfs/etc/crucible-debug-sshd_config <<'SSHD_CONFIG'
          HostKey /run/crucible-debug-ssh-host-key
          PidFile none
          UsePAM no
          PermitRootLogin yes
          PermitEmptyPasswords yes
          PasswordAuthentication yes
          KbdInteractiveAuthentication no
          PubkeyAuthentication no
          StrictModes no
          PrintMotd no
          PrintLastLog no
          X11Forwarding no
          AllowTcpForwarding no
          AllowAgentForwarding no
          PermitTunnel no
          Subsystem sftp internal-sftp
          SSHD_CONFIG

          cat > rootfs/usr/sbin/crucible-debug-sshd <<'DEBUG_SSHD'
          #!${bash}/bin/bash
          set -euo pipefail

          host_key=/run/crucible-debug-ssh-host-key
          [[ -f "$host_key" ]] || {
            echo 'Crucible debug SSH host key is unavailable' >&2
            exit 1
          }
          exec ${openssh}/sbin/sshd -i -e -f /etc/crucible-debug-sshd_config
          DEBUG_SSHD
          chmod +x rootfs/usr/sbin/crucible-debug-sshd

          cat > rootfs/etc/crucible-fixture.env <<'ENV'
          CRUCIBLE_FIXTURE_NAME=${fixtureName}
          CRUCIBLE_STORE_MOUNT_TAG=${hostStoreMountTag}
          CRUCIBLE_ENTROPY_FW_CFG=opt/crucible/seed
          CRUCIBLE_ENTROPY_SEED_FILE=${entropySeedFileName}
          CRUCIBLE_MAC_DERIVATION=sha256-root-image-sha256
          ENV
          doorbell_instruction_abi_version=$(sed -n \
            's/^doorbell_instruction_abi_version=\([0-9][0-9]*\)$/\1/p' \
            ${crucible-guest}/nix-support/crucible-guest-build-info)
          test -n "$doorbell_instruction_abi_version"
          printf 'CRUCIBLE_DOORBELL_INSTRUCTION_ABI_VERSION=%s\n' \
            "$doorbell_instruction_abi_version" >> rootfs/etc/crucible-fixture.env

          cat > rootfs/init <<'INIT'
          #!/bin/sh
          set -eu

          export PATH="${fixtureBootPath}"
          export HOME=/tmp

          mkdir -p /proc /sys /dev /run /root /tmp /nix/store /mnt/host-store
          mount -t proc proc /proc || true
          mount -t sysfs sysfs /sys || true
          mount -t devtmpfs devtmpfs /dev || true
          mkdir -p /dev/pts
          mount -t devpts devpts /dev/pts || true
          mount -t tmpfs tmpfs /run || true
          ${openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f /run/crucible-debug-ssh-host-key

          if mount -t 9p -o trans=virtio,version=9p2000.L,cache=none,ro ${hostStoreMountTag} /nix/store; then
            echo 'CRUCIBLE_9P_STORE_READY'
          else
            echo 'CRUCIBLE_9P_STORE_UNAVAILABLE'
          fi

          echo 'CRUCIBLE_FIXTURE_READY'
          if [ -x ${crucible-guest}/bin/crucible-guest ]; then
            ${crucible-guest}/bin/crucible-guest setup-complete || true
          fi
          echo 'CRUCIBLE_FIXTURE_DONE'

          if [ -w /proc/sys/kernel/hotplug ]; then
            echo /sbin/crucible-debug-hotplug > /proc/sys/kernel/hotplug
          else
            echo 'CRUCIBLE_DEBUG_AGENT_HOTPLUG_UNAVAILABLE'
          fi

          # The activation-only port is fixed in the canonical topology. Start
          # one blocking reader after setup so canonical execution performs no
          # polling and only a committed debug fork can deliver the token.
          for name_file in /sys/class/virtio-ports/*/name; do
            if [ -f "$name_file" ] && [ "$(cat "$name_file")" = 'org.aos.crucible.debug' ]; then
              port=$(basename "$(dirname "$name_file")")
              ACTION=add DEVPATH="/class/virtio-ports/$port" /sbin/crucible-debug-hotplug
              echo 'CRUCIBLE_DEBUG_ACTIVATION_READER_READY'
            fi
          done

          while :; do
            :
          done
          INIT
          chmod +x rootfs/init

          cat > rootfs/sbin/crucible-debug-hotplug <<'HOTPLUG'
          #!/bin/sh
          set -eu

          if [ "''${ACTION:-}" != add ]; then
            exit 0
          fi
          name_file="/sys''${DEVPATH:?missing hotplug device path}/name"
          if [ ! -f "$name_file" ]; then
            name_file="/sys/class/virtio-ports/$(basename "''${DEVPATH}")/name"
          fi
          if [ ! -f "$name_file" ] || [ "$(cat "$name_file")" != 'org.aos.crucible.debug' ]; then
            exit 0
          fi
          activation_port="/dev/$(basename "''${DEVPATH}")"
          (
            echo "CRUCIBLE_DEBUG_ACTIVATION_READER_OPEN port=$activation_port"
            IFS= read -r activation_token < "$activation_port"
            if [ "$activation_token" != 'CRUCIBLE_DEBUG_AGENT_V1' ]; then
              echo 'CRUCIBLE_DEBUG_AGENT_ACTIVATION_REJECTED'
              exit 1
            fi
            echo 'CRUCIBLE_DEBUG_AGENT_ACTIVATED'
            exec ${crucible-guest}/bin/crucible-guest agent \
              --ssh-program /usr/sbin/crucible-debug-sshd
          ) &
          HOTPLUG
          chmod +x rootfs/sbin/crucible-debug-hotplug

          mkdir -p third-party-rootfs/bin third-party-rootfs/dev third-party-rootfs/etc
          mkdir -p third-party-rootfs/nix/store third-party-rootfs/proc third-party-rootfs/run
          mkdir -p third-party-rootfs/sys third-party-rootfs/tmp third-party-rootfs/var/tmp

          copy_closure third-party-closure third-party-rootfs

          ln -sfn ${bash}/bin/bash third-party-rootfs/bin/sh
          ln -sfn ${bash}/bin/bash third-party-rootfs/bin/bash

          cat > third-party-rootfs/init <<'THIRD_PARTY_INIT'
          #!/bin/sh
          set -eu

          export PATH="${thirdPartyBootPath}"
          export HOME=/tmp

          mkdir -p /proc /sys /dev /run /tmp
          mount -t proc proc /proc || true
          mount -t sysfs sysfs /sys || true
          mount -t devtmpfs devtmpfs /dev || true
          mount -t tmpfs tmpfs /run || true

          echo 'AOS_GENERIC_ANY_GUEST_READY'
          echo 'AOS_GENERIC_ANY_GUEST_DONE'

          while :; do
            :
          done
          THIRD_PARTY_INIT
          chmod +x third-party-rootfs/init

          mkdir -p \
            "$out/share/crucible/fixtures/entropy" \
            "$out/share/crucible/fixtures/root" \
            "$out/share/crucible/fixtures/qemu" \
            "$out/share/crucible/fixtures/third-party-guests/${thirdPartyGuestName}" \
            "$out/nix-support"

          printf '\020\246\135\174\003\021\377\240\124\253\105\011\202\067\330\016\265\271\143\117\224\001\122\055\316\100\271\005\176\163\072\221' \
            > "$out/${entropySeedRelativePath}"
          seed_size=$(wc -c < "$out/${entropySeedRelativePath}" | tr -d ' ')
          if [ "$seed_size" != 32 ]; then
            echo "crucible-fixtures: entropy seed artifact must be 32 bytes, got $seed_size" >&2
            exit 1
          fi

          cat > "$out/share/crucible/fixtures/qemu/launch-fragment.txt" <<'QEMU'
          ${qemuLaunchFragment}
          QEMU

          cat > "$out/share/crucible/fixtures/qemu/prepare-cow-overlay" <<'COW_OVERLAY'
          ${cowOverlayScript}
          COW_OVERLAY
          chmod +x "$out/share/crucible/fixtures/qemu/prepare-cow-overlay"

          make_image rootfs crucible-root "$out/${rootImageRelativePath}"
          root_hash=$(image_sha256 "$out/${rootImageRelativePath}")
          printf '%s\n' "$root_hash" > "$out/share/crucible/fixtures/root/${fixtureName}-root.ext4.sha256"
          stat -c %s "$out/${rootImageRelativePath}" > "$out/share/crucible/fixtures/root/${fixtureName}-root-size-bytes"
          root_node_id="sha256:$root_hash"
          root_mac=$(mac_from_hash "$root_hash")

          make_image third-party-rootfs aos-any-guest "$out/${thirdPartyRootImageRelativePath}"
          third_party_hash=$(image_sha256 "$out/${thirdPartyRootImageRelativePath}")
          printf '%s\n' "$third_party_hash" > "$out/share/crucible/fixtures/third-party-guests/${thirdPartyGuestName}/root.ext4.sha256"
          stat -c %s "$out/${thirdPartyRootImageRelativePath}" > "$out/share/crucible/fixtures/third-party-guests/${thirdPartyGuestName}/root-size-bytes"
          third_party_node_id="sha256:$third_party_hash"
          third_party_mac=$(mac_from_hash "$third_party_hash")

          cat > "$out/share/crucible/fixtures/manifest.toml" <<MANIFEST
          [fixture]
          name = "${fixtureName}"
          package = "crucible-fixtures"
          root_image = "${rootImageRelativePath}"
          root_image_format = "ext4"
          root_image_sha256 = "$root_hash"
          read_only_base = true
          copy_on_write_boot = true
          virtio_9p_store_share = true
          virtio_9p_mount_tag = "${hostStoreMountTag}"
          ext4_feature_flags = "-O ${ext4FeatureFlags}"
          init_shebang = "/bin/sh"
          init_kernel_arg = "init=/init"
          init_shell_target = "${bash}/bin/bash"
          userland = "AOS bash plus AOS coreutils/util-linux boot closure"
          host_store_share = "/nix/store via virtio-9p readonly=on"
          qemu_overlay_format = "qcow2"
          qemu_overlay_prepare = "share/crucible/fixtures/qemu/prepare-cow-overlay"

          [entropy]
          mechanism = "${entropySeedMechanism}"
          seed_artifact = "${entropySeedRelativePath}"
          fw_cfg_name = "opt/crucible/seed"
          qemu_rng = "rng-builtin seeded by -seed"
          host_entropy_sources = "disabled"

          [[nodes]]
          name = "${fixtureName}"
          content_addressed_node_id = "$root_node_id"
          mac_address = "$root_mac"
          mac_derivation = "sha256(root-image-sha256)"

          [[nodes]]
          name = "${thirdPartyGuestName}"
          content_addressed_node_id = "$third_party_node_id"
          mac_address = "$third_party_mac"
          mac_derivation = "sha256(root-image-sha256)"
          unmodified_third_party_guest_path = "${thirdPartyGuestPath}"
          exercised_by_gate = "checks.crucible.phase2.gates.anyGuest"
          MANIFEST

          cat > "$out/${thirdPartyGuestPath}" <<THIRD_PARTY
          name = "${thirdPartyGuestName}"
          root_image = "${thirdPartyRootImageRelativePath}"
          root_image_sha256 = "$third_party_hash"
          image_policy = "unmodified"
          in_guest_crucible_content_required = false
          stock_kernel_and_image = true
          content_addressed_node_id = "$third_party_node_id"
          mac_address = "$third_party_mac"
          mac_derivation = "sha256(root-image-sha256)"
          exercised_by_gate = "checks.crucible.phase2.gates.anyGuest"
          THIRD_PARTY

          cat > "$out/nix-support/crucible-fixtures" <<INFO
          package=crucible-fixtures
          doorbell_instruction_abi_version=$doorbell_instruction_abi_version
          root_image=${rootImageRelativePath}
          root_image_sha256=$root_hash
          read_only_base=true
          copy_on_write_boot=true
          virtio_9p_store_share=true
          virtio_9p_mount_tag=${hostStoreMountTag}
          ext4_features=-O ${ext4FeatureFlags}
          entropy_seed_mechanism=${entropySeedMechanism}
          entropy_seed_artifact=${entropySeedRelativePath}
          node_mac_derivation=sha256-root-image-sha256
          third_party_guest_path=${thirdPartyGuestPath}
          third_party_root_image=${thirdPartyRootImageRelativePath}
          third_party_root_image_sha256=$third_party_hash
          INFO
        '';
      }
    ];

    meta = {
      description = "Minimal Crucible deterministic guest root-image fixtures";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }

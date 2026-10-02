##! pkgs/system/_systemd-abilities/platform/_initrd-builder.nix — Tier-ii systemd initrd builder
##!
##! Builds a zstd-compressed cpio initramfs from pure Nix-store paths —
##! no VM, no losetup. The archive is assembled from a directory tree
##! populated from:
##!
##!   1. The full runtime closure of each initrd package (bash, coreutils,
##!      cryptsetup, e2fsprogs, kmod, systemd, util-linux) copied
##!      under /nix/store/. Store RPATHs make ld.so happy without any
##!      ELF-walking or rpath rewriting.
##!   2. `/bin/<name>` symlinks into those closures so systemd units and
##!      ExecStart paths can reference short names when needed.
##!   3. The active kernel's module tree at /lib/modules/<ver>/.
##!   4. `/etc/modules-load.d/initrd.conf` listing `aos.boot.initrd.loadModules`.
##!   5. Empty `/etc/fstab` (root device comes from the kernel cmdline
##!      `root=` parameter; the fstab generator processes it).
##!   6. Minimal `/etc/{os-release,initrd-release,passwd,group,shadow}`.
##!   7. Upstream systemd initrd units symlinked from ${systemd}/lib/systemd/
##!      system/ into /etc/systemd/system/. (AOS systemd ships units at
##!      lib/systemd/system/, while generateUnits renders the package-owned
##!      image bootstrap unit declarations.)
##!   8. The output of `generateUnits` for the rendered initrd units —
##!      `boot.initrd.systemd.services` etc. resolved through the stage-1
##!      ToUnit renderers.
##!   9. The exact native initrd transaction, selected package closure, and
##!      admission receipt authenticated by the verified image.
##! Arguments:
##!   pkgs          — AOS package set
##!   lib           — AOS library
##!   kernel        — exact selected kernel projection
##!   loadModules — list of module names for /etc/modules-load.d/initrd.conf
##!   initrdUnits   — derivation whose output is the rendered
##!                   /etc/systemd/system directory (from generateUnits)
##!   initrdRuntimeRoots — canonical store paths whose closures are copied
##!                   into the initrd and exposed on its interactive PATH.
##!   initrdNetworkDir — native network bootstrap directory containing
##!                   rendered systemd-networkd `.network` files; copied into
##!                   /etc/systemd/network/. Null/absent ⇒ no networkd config.
##!   deploymentBundle — immutable native transaction and admission inputs.
##!   registration — exact Nix registration stream for the copied closure.
##!
##! Output: $out/initrd.img (zstd-compressed newc cpio archive)
{
  lib,
  mkDerivation,
  runtimePackages,
  kernel,
  kernelModulePackages ? [],
  firmwarePackages ? [],
  loadModules,
  initrdUnits,
  initrdRuntimeRoots,
  initrdNetworkDir ? null,
  handoff,
  accountSeed,
  deploymentBundle,
  registration,
  maskedUnits ? [],
  validateBootIdentity ? false,
}: let
  kernelPackage = kernel.package;
  kernelModuleTree =
    if kernel.configuration.moduleTree == null
    then throw "systemd initrd requires a selected kernel module tree"
    else kernel.configuration.moduleTree;
  kernelRelease = kernel.configuration.release;
  inherit
    (runtimePackages)
    bash
    coreutils
    cpio
    cryptsetup
    e2fsprogs
    findutils
    gawk
    gptfdisk
    grep
    iproute2
    jq
    kmod
    less
    nix
    systemd
    util-linux
    zstd
    ;
  dependencyRoots =
    [
      {
        kind = "kernel";
        store_path = "${kernelPackage}";
        available_stage = "build";
      }
      {
        kind = "unit-configuration";
        store_path = "${initrdUnits}";
        available_stage = "build";
      }
    ]
    ++ lib.optional (initrdNetworkDir != null) {
      kind = "network-configuration";
      store_path = "${initrdNetworkDir}";
      available_stage = "build";
    }
    ++ map (package: {
      kind = "runtime-package";
      store_path = "${package}";
      available_stage = "initrd";
    })
    initrdRuntimeRoots
    ++ map (package: {
      kind = "kernel-module-package";
      store_path = "${package}";
      available_stage = "build";
    })
    kernelModulePackages
    ++ map (package: {
      kind = "firmware-package";
      store_path = "${package}";
      available_stage = "build";
    })
    firmwarePackages;

  # Short /bin/<name> symlinks. A binary only needs to appear here if an
  # initrd unit (or a script invoked by one) references it as `/bin/foo`
  # rather than as an absolute store path. Keep it conservative — the
  # store paths work anywhere.
  initrdBinaries = [
    {
      pkg = nix;
      bin = "nix-instantiate";
      src = "bin";
    }
    {
      pkg = util-linux;
      bin = "prlimit";
      src = "bin";
    }
    {
      pkg = bash;
      bin = "bash";
      src = "bin";
    }
    {
      pkg = bash;
      bin = "sh";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "cat";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "cp";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "ln";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "ls";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "mkdir";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "mv";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "rm";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "test";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "touch";
      src = "bin";
    }
    {
      pkg = coreutils;
      bin = "sleep";
      src = "bin";
    }
    {
      pkg = util-linux;
      bin = "mount";
      src = "bin";
    }
    {
      pkg = util-linux;
      bin = "umount";
      src = "bin";
    }
    {
      pkg = util-linux;
      bin = "blkid";
      src = "sbin";
    }
    {
      pkg = util-linux;
      bin = "lsblk";
      src = "bin";
    }
    {
      pkg = util-linux;
      bin = "sfdisk";
      src = "sbin";
    }
    {
      pkg = util-linux;
      bin = "mkswap";
      src = "sbin";
    }
    {
      pkg = util-linux;
      bin = "swapon";
      src = "sbin";
    }
    {
      pkg = iproute2;
      bin = "ip";
      src = "sbin";
    }
    {
      pkg = kmod;
      bin = "modprobe";
      src = "sbin";
    }
    {
      pkg = kmod;
      bin = "insmod";
      src = "sbin";
    }
    {
      pkg = kmod;
      bin = "lsmod";
      src = "sbin";
    }
    {
      pkg = e2fsprogs;
      bin = "mkfs.ext4";
      src = "sbin";
    }
    {
      pkg = e2fsprogs;
      bin = "resize2fs";
      src = "sbin";
    }
    {
      pkg = e2fsprogs;
      bin = "e2fsck";
      src = "sbin";
    }
    {
      pkg = cryptsetup;
      bin = "cryptsetup";
      src = "sbin";
    }
    {
      pkg = gptfdisk;
      bin = "sgdisk";
      src = "sbin";
    }
  ];

  # Upstream systemd units imported from ${systemd}/lib/systemd/system/
  # into the initrd's /etc/systemd/system/. AOS's generateUnits cannot
  # fold these in for type=initrd (it looks under example/systemd/,
  # which AOS does not populate), so the builder symlinks them manually.
  # Any unit listed here must exist in the systemd package — the builder
  # fails if one is missing.
  initrdUpstreamUnits = [
    "initrd.target"
    "initrd-fs.target"
    "initrd-root-fs.target"
    "initrd-root-device.target"
    "initrd-usr-fs.target"
    "initrd-switch-root.target"
    "initrd-switch-root.service"
    "initrd-cleanup.service"
    "initrd-parse-etc.service"
    # sysroot.mount is NOT shipped as a static unit — it is synthesized
    # at runtime by systemd-fstab-generator from /etc/fstab (see the
    # fstab entry the builder writes above).
    "systemd-udevd.service"
    "systemd-udevd-control.socket"
    "systemd-udevd-kernel.socket"
    "systemd-udev-trigger.service"
    "systemd-udev-settle.service"
    "systemd-modules-load.service"
    "systemd-tmpfiles-setup.service"
    "systemd-tmpfiles-setup-dev.service"
    "systemd-journald.service"
    "systemd-journald.socket"
    "systemd-journald-dev-log.socket"
    "systemd-sysctl.service"
    "sysinit.target"
    "basic.target"
    "local-fs.target"
    "local-fs-pre.target"
    "paths.target"
    "slices.target"
    "sockets.target"
    "timers.target"
    "swap.target"
    "emergency.target"
    "emergency.service"
    "rescue.target"
    "rescue.service"
    "breakpoint-pre-switch-root.service"
    "breakpoint-pre-mount.service"
    "breakpoint-pre-basic.service"
    "breakpoint-pre-udev.service"
    "debug-shell.service"
    "kmod-static-nodes.service"
    "systemd-ask-password-console.path"
    "systemd-ask-password-console.service"
    # Stage-1 networking for metadata fetch on cloud platforms.
    # The aos-metadata-network gate issues a
    # blocking `systemctl start network-online.target` only when the detector
    # flags a network-dependent platform; these units are the closure it pulls.
    "network-pre.target"
    "network.target"
    "network-online.target"
    "systemd-networkd.service"
    "systemd-networkd.socket"
    "systemd-networkd-wait-online.service"
  ];

  # Systemd generators that must be present in the initrd so fstab-based
  # sysroot.mount synthesis works and auto-discovery kicks in.
  initrdGenerators = [
    "systemd-fstab-generator"
    "systemd-gpt-auto-generator"
  ];

  # Render the (pkg, binary, src) triples into `ln -sfn` invocations.
  binarySymlinks =
    lib.concatMapStringsSep "\n" (e: "ln -sfn ${e.pkg}/${e.src}/${e.bin} root/bin/${e.bin}")
    initrdBinaries;

  # Upstream unit symlinks go into /lib/systemd/system/ (not /etc/) so AOS's
  # explicit /etc masks and drop-ins retain higher priority. Production
  # initrds deliberately omit systemd-debug-generator, so command-line masks
  # cannot rewrite the stage-1 unit graph.
  unitSymlinks =
    lib.concatMapStringsSep "\n" (u: ''
      if [ ! -e ${systemd}/lib/systemd/system/${u} ]; then
        echo "initrd-builder: upstream systemd unit missing: ${u}" >&2
        exit 1
      fi
      ln -sfn ${systemd}/lib/systemd/system/${u} root/lib/systemd/system/${u}
    '')
    initrdUpstreamUnits;

  generatorSymlinks =
    lib.concatMapStringsSep "\n" (g: ''
      if [ ! -e ${systemd}/lib/systemd/system-generators/${g} ]; then
        echo "initrd-builder: upstream systemd generator missing: ${g}" >&2
        exit 1
      fi
      ln -sfn ${systemd}/lib/systemd/system-generators/${g} \
        root/lib/systemd/system-generators/${g}
    '')
    initrdGenerators;

  modulesLoadConf = lib.concatStringsSep "\n" loadModules;

  completionUnit = handoff.realization.completion_unit.unit_name;
  requiredUnits = builtins.map (unit: unit.unit_name) handoff.realization.required_units;
  stageInputPaths = handoff.paths.initrd;
  stageBundleDestination = lib.escapeShellArg ("root" + stageInputPaths.bundle);
  stageBundleParent = lib.escapeShellArg ("root" + builtins.dirOf stageInputPaths.bundle);
  requiredUnitChecks =
    lib.concatMapStringsSep "\n" (unit: ''
      unit_path=root/etc/systemd/system/${unit}
      requirement_path=root/etc/systemd/system/${completionUnit}.requires/${unit}
      if [ ! -f "$unit_path" ]; then
        echo "initrd-builder: required handoff unit is not rendered: ${unit}" >&2
        exit 1
      fi
      if [ ! -L "$requirement_path" ]; then
        echo "initrd-builder: ${completionUnit} does not require ${unit}" >&2
        exit 1
      fi
      unit_target=$(readlink -f "$unit_path")
      requirement_target=$(readlink -f "$requirement_path")
      if [ "$requirement_target" != "$unit_target" ]; then
        echo "initrd-builder: ${completionUnit} requirement does not resolve to ${unit}" >&2
        exit 1
      fi
      if ! awk -v target=${lib.escapeShellArg completionUnit} '
        /^[[:space:]]*\[/ {
          in_unit = ($0 ~ /^[[:space:]]*\[Unit\][[:space:]]*$/)
          next
        }
        in_unit && /^[[:space:]]*Before[[:space:]]*=/ {
          value = $0
          sub(/^[^=]*=/, "", value)
          if (value ~ /^[[:space:]]*$/) {
            found = 0
            next
          }
          count = split(value, tokens, /[[:space:]]+/)
          for (token_index = 1; token_index <= count; token_index++) {
            if (tokens[token_index] == target) found = 1
          }
        }
        END { exit found ? 0 : 1 }
      ' "$unit_path"; then
        echo "initrd-builder: ${unit} is not ordered before ${completionUnit}" >&2
        exit 1
      fi
    '')
    requiredUnits;

  interactivePath = lib.concatStringsSep ":" (
    (map (p: "${p}/bin") initrdRuntimeRoots)
    ++ (map (p: "${p}/sbin") initrdRuntimeRoots)
    ++ ["/bin" "/sbin"]
  );
  initrdArchive = mkDerivation {
    name = "aos-initrd-archive";
    src = null;

    buildDeps = [
      cpio
      zstd
      coreutils
      findutils
      gawk
      jq
    ];

    # Catalogs inside the compressed image name available outputs that are
    # not runtime roots. A compressed hash can accidentally survive Nix's
    # byte scanner; retain dependencies explicitly in the public wrapper.
    outputChecks.out = {};
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "populate";
        script = ''
          set -euo pipefail

          echo "==> Assembling AOS systemd initrd"

          # Copy exactly the same realized closure that the guest registers.
          cp ${registration}/store-paths closure-paths
          echo "    $(wc -l < closure-paths) unique store paths in initrd closure"

          # ── 1. Directory skeleton ───────────────────────────────────────
          mkdir -p root/bin
          mkdir -p root/sbin
          mkdir -p root/etc/systemd/system
          mkdir -p root/etc/modules-load.d
          mkdir -p root/lib/systemd/system
          mkdir -p root/lib/systemd/system-generators
          mkdir -p root/lib/aos
          printf 'aos.config-bundle/v1\n' > root/lib/aos/configuration-capabilities
          mkdir -p root/lib/modules
          mkdir -p root/nix/store
          mkdir -p root/proc root/sys root/dev root/run root/tmp root/sysroot root/var
          mkdir -p -m 700 root/root

          # /usr → . so /usr/lib/<...> paths resolve to /lib/<...>. systemd
          # and several helpers synthesise /usr paths internally.
          ln -s . root/usr

          # /sbin/init is systemd itself. The kernel also looks for
          # /init at the archive root (rdinit=/init defaults), so a
          # missing top-level /init makes the kernel silently skip the
          # initramfs with "check access for rdinit=/init failed: -2,
          # ignoring" and boot straight from root=. Symlink it too.
          ln -sfn ${systemd}/lib/systemd/systemd root/sbin/init
          ln -sfn ${systemd}/lib/systemd/systemd root/init

          # ── 2. Copy the full runtime closures of all initrd packages ────
          total=$(wc -l < closure-paths)
          count=0
          while IFS= read -r p; do
            count=$((count + 1))
            if [ $((count % 50)) -eq 0 ] || [ "$count" -eq "$total" ]; then
              printf '    [%d/%d] %s\n' "$count" "$total" "$(basename "$p")"
            fi
            cp -a "$p" root"$p"
          done < closure-paths

          # udev only searches its configured vendor directory plus the
          # conventional /etc and /run override directories. Dependencies
          # such as device-mapper install rules beneath their own immutable
          # prefixes, so collect those rules into the initrd's vendor view.
          # Without 10-dm.rules/13-dm-disk.rules, veritysetup can create
          # /dev/dm-0 while systemd waits forever for dev-mapper-root.device.
          mkdir -p root/lib/udev/rules.d
          for rules_dir in root/nix/store/*/lib/udev/rules.d; do
            [ -d "$rules_dir" ] || continue
            for rule in "$rules_dir"/*.rules; do
              [ -e "$rule" ] || continue
              name=$(basename "$rule")
              target="/''${rule#root/}"
              if [ -e "root/lib/udev/rules.d/$name" ]; then
                echo "initrd-builder: duplicate udev rule $name" >&2
                exit 1
              fi
              ln -s "$target" "root/lib/udev/rules.d/$name"
            done
          done

          # ── 3. Short /bin symlinks for the binaries we need by name ────
          ${binarySymlinks}

          # ── 4. Kernel modules ──────────────────────────────────────────
          if [ -d ${kernelModuleTree} ]; then
            mkdir -p root/lib/modules/${kernelRelease}
            cp -a ${kernelModuleTree}/. root/lib/modules/${kernelRelease}/
            find root/lib/modules -type d -exec chmod u+w {} +
          else
            echo "initrd-builder: selected kernel module tree ${kernelModuleTree} not found" >&2
            exit 1
          fi
          ${lib.concatMapStringsSep "\n" (package: ''
              if [ ! -d ${package}/lib/modules ]; then
                echo "initrd-builder: external module package ${package} has no module tree" >&2
                exit 1
              fi
              find root/lib/modules -type d -exec chmod u+w {} +
              cp -a ${package}/lib/modules/. root/lib/modules/
            '')
            kernelModulePackages}
          for module_dir in root/lib/modules/*; do
            # External module packages may restore the copied release
            # directory's read-only store mode after the kernel tree was
            # made writable. Only the parent directory needs write access
            # to unlink the build/source symlinks; recursively chmodding does
            # not follow those symlinks and therefore cannot repair it.
            chmod u+w root/lib/modules "$module_dir"
            rm -f "$module_dir/build" "$module_dir/source"
            ${kmod}/sbin/depmod -b root "$(basename "$module_dir")"
          done

          # Firmware selected specifically for early storage, network, and TPM drivers.
          mkdir -p root/lib/firmware
          ${lib.concatMapStringsSep "\n" (package: ''
              if [ ! -d ${package}/lib/firmware ]; then
                echo "initrd-builder: firmware package ${package} has no firmware tree" >&2
                exit 1
              fi
              cp -a ${package}/lib/firmware/. root/lib/firmware/
            '')
            firmwarePackages}

          # ── 5. /etc skeleton ───────────────────────────────────────────
          cat > root/etc/modules-load.d/initrd.conf <<MODULES
          ${modulesLoadConf}
          MODULES

          # The root device is specified via root= on the kernel cmdline.
          # systemd-fstab-generator processes root= and synthesises
          # sysroot.mount with proper initrd-root-fs.target linkage.
          # An /etc/fstab entry for root would conflict (duplicate
          # sysroot.mount) and make the generator exit 1, breaking the
          # initrd target chain. Write an empty fstab so the generator
          # has nothing to conflict with.
          touch root/etc/fstab

          cat > root/etc/os-release <<OSREL
          NAME="AOS"
          ID=aos
          PRETTY_NAME="ANDYL OS (initrd)"
          OSREL
          cp root/etc/os-release root/etc/initrd-release

          mkdir -p ${stageBundleParent}
          ln -s ${deploymentBundle} ${stageBundleDestination}
          install -D -m 0444 ${registration}/registration root/lib/aos/initrd/registration
          registrationDigest=$(sha256sum root/lib/aos/initrd/registration)
          printf '%s\n' "''${registrationDigest%% *}" > root/lib/aos/initrd/registration.sha256
          mkdir -p root/nix/var/nix/db root/nix/var/nix/gcroots

          # Make the interactive stage-1 recovery shells usable:
          cat > root/etc/profile <<PROFILE
          export PATH="${interactivePath}"
          export PAGER=less
          PROFILE

          # /etc/hosts — localhost plus GCP's metadata.google.internal, which
          # is the one cloud metadata endpoint reached by name rather than IP
          # literal. No stage-1 DNS resolver, so this static map stands in.
          cat > root/etc/hosts <<'HOSTS'
          127.0.0.1 localhost
          ::1 localhost
          169.254.169.254 metadata.google.internal metadata
          HOSTS

          cat > root/etc/machine-id <<'MACHINEID'
          MACHINEID

          # ── 6. Upstream systemd units and generators ───────────────────
          ${unitSymlinks}
          ${generatorSymlinks}

          ${lib.optionalString validateBootIdentity ''
            # Keep the upstream verity implementation under a private,
            # non-generator name. A runtime service invokes it only after
            # procfs and /run are authoritative, validates its exact root-unit
            # output, and makes that unit actionable behind the identity guard.
            cp ${systemd}/lib/systemd/system-generators/systemd-veritysetup-generator \
              root/lib/systemd/aos-systemd-veritysetup-generator
            chmod 0755 root/lib/systemd/aos-systemd-veritysetup-generator
          ''}

          # ── 7. Rendered initrd units from boot.initrd.systemd.* ────────
          # Matches generateUnits output — a directory whose entries are
          # unit files and dependency directories (*.wants, *.requires).
          if [ -d ${initrdUnits} ]; then
            cp -a ${initrdUnits}/. root/etc/systemd/system/ || true
          fi

          # ── 7a. Network configuration rendered from native bootstrap policy.
          mkdir -p root/etc/systemd/network
          ${lib.optionalString (initrdNetworkDir != null) ''
            if [ -d ${initrdNetworkDir} ]; then
              cp -a ${initrdNetworkDir}/. root/etc/systemd/network/ || true
            fi
          ''}

          # ── 7c. Enable systemd-networkd-wait-online via network-online.target.
          #    [Install] sections of systemd's packaged units aren't realized
          #    in the initrd, so this .wants symlink makes `systemctl start
          #    network-online.target` pull in wait-online → networkd. The
          #    rendered-units copy above left /etc/systemd/system read-only
          #    (store perms), so make it writable before adding the subdir.
          chmod u+w root/etc/systemd/system
          mkdir -p root/etc/systemd/system/network-online.target.wants
          ln -sfn /lib/systemd/system/systemd-networkd-wait-online.service \
            root/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service
          # ── 8. Masked units ─────────────────────────────────────────────
          chmod u+w root/etc/systemd/system
          ${lib.concatMapStringsSep "\n" (u: ''
              rm -f root/etc/systemd/system/${u} root/lib/systemd/system/${u}
              ln -sfn /dev/null root/etc/systemd/system/${u}
            '')
            maskedUnits}

          # A weak upstream Wants permits switch-root after a failed filesystem
          # transaction. The selected handoff completion target must succeed.
          mkdir -p root/etc/systemd/system/initrd-switch-root.target.d
          printf '%s\n' '[Unit]' \
            ${lib.escapeShellArg "Requires=${completionUnit}"} \
            ${lib.escapeShellArg "After=${completionUnit}"} \
            > root/etc/systemd/system/initrd-switch-root.target.d/50-aos-handoff.conf

          # The contract describes the rendered graph, so validate the actual
          # unit files and dependency links after every copy and mask step.
          ${requiredUnitChecks}

          # Admission verifies exact NAR identities. Every retained immutable
          # output must survive assembly byte-for-byte, including nonexecutables.
          test -f root${lib.packageModuleLibrary}/default.nix

          # Stage admission invokes the exact selected package handlers.
          # Resolve them from the sealed package documents after trimming.
          # A symlink could otherwise resolve against the build host's store
          # instead of an entry retained in the archive.
          ${jq}/bin/jq -r \
            '.graph.nodes[] | select(.handler.kind == "process") | .handler.executable' \
            ${deploymentBundle}/transaction.json \
            | sort -u \
            | while IFS= read -r executable; do
                test ! -L "root$executable" \
                  && test -f "root$executable" \
                  && test -x "root$executable" || {
                  echo "initrd-builder: native handler $executable is absent" >&2
                  exit 1
                }
              done
        '';
      }
      {
        name = "seed-accounts";
        script = ''
          # Preserve the complete native seed texts exactly: an extra newline
          # creates an empty account row rejected by the identity provider.
          printf '%s' ${lib.escapeShellArg accountSeed.passwd} > root/etc/passwd
          printf '%s' ${lib.escapeShellArg accountSeed.group} > root/etc/group
          printf '%s' ${lib.escapeShellArg accountSeed.shadow} > root/etc/shadow
          # The archive assigns uid 0; the builder needs read access for cpio.
          chmod 0600 root/etc/shadow
        '';
      }
      {
        name = "create-cpio";
        script = ''
          set -euo pipefail
          mkdir -p $out

          echo "==> Packing cpio archive"
          # Reproducible timestamps — every entry epoch 1.
          find root -exec touch -h -d '@1' '{}' +

          # cpio -R +0:+0 forces uid/gid 0; --reproducible zeroes inodes and
          # device numbers. Sort the file list so the archive order is
          # deterministic across builds.
          #
          # zstd -19 is the strongest level whose decompression window
          # (8 MiB, windowLog 23) is universally accepted by the kernel's
          # CONFIG_RD_ZSTD initramfs decompressor — the proven maximum used
          # by dracut/mkinitcpio. (`--ultra -22` is ~1-3% smaller but uses a
          # 128 MiB window; only adopt it with a boot test.) We run
          # single-threaded on purpose: zstd is bit-reproducible only for a
          # fixed thread count, and $NIX_BUILD_CORES varies between builders,
          # so multithreading would break the deterministic-output guarantee
          # that measured boot and the binary cache rely on. zstd writes no
          # timestamps, so the stream is reproducible by default.
          (
            cd root \
              && find . -print0 \
              | LC_ALL=C sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | zstd -19 -q -c > $out/initrd.img
          )

          archive_size=$(stat -c %s "$out/initrd.img")
          archive_sha256=$(sha256sum "$out/initrd.img" | cut -d ' ' -f1)
          rendered_networks=$(
            ${findutils}/bin/find root/etc/systemd/network \
              -maxdepth 1 -type f -printf '%f\n' \
              | LC_ALL=C ${coreutils}/bin/sort \
              | ${jq}/bin/jq -Rsc 'split("\n") | map(select(length > 0))'
          )
          # Provider units are materialized after the pure option renderer, so
          # inventory the actual unit directory that enters the archive.
          rendered_units=$(
            ${findutils}/bin/find root/etc/systemd/system \
              -maxdepth 1 \( -type f -o -type l \) -printf '%f\n' \
              | LC_ALL=C ${coreutils}/bin/sort \
              | ${jq}/bin/jq -Rsc 'split("\n") | map(select(length > 0))'
          )
          ${jq}/bin/jq -cS -n \
            --arg schema aos.boot.initrd-stage-contract/v1 \
            --arg platform ${lib.escapeShellArg kernel.targetPlatform.system} \
            --arg kernelRelease ${lib.escapeShellArg kernelRelease} \
            --arg archiveSha256 "sha256:$archive_sha256" \
            --argjson archiveSize "$archive_size" \
            --argjson dependencyRoots ${lib.escapeShellArg (builtins.toJSON dependencyRoots)} \
            --argjson renderedUnits "$rendered_units" \
            --argjson renderedNetworks "$rendered_networks" \
            --argjson loadModules ${lib.escapeShellArg (builtins.toJSON loadModules)} \
            --argjson maskedUnits ${lib.escapeShellArg (builtins.toJSON maskedUnits)} \
            --argjson handoff ${lib.escapeShellArg (builtins.toJSON handoff)} \
            '($dependencyRoots
               | unique_by([.kind,.store_path,.available_stage])
               | sort_by([.kind,.store_path,.available_stage])) as $dependencies
             | {schema_version:$schema,stage:"initrd",platform:$platform,
                kernel_release:$kernelRelease,
                artifact:{path:"initrd.img",size_bytes:$archiveSize,sha256:$archiveSha256},
                dependency_roots:$dependencies,
                rendered_units:($renderedUnits
                  | map(select(. as $unit | ($maskedUnits | index($unit)) == null))
                  | sort | unique),
                rendered_networks:($renderedNetworks | sort | unique),
                load_modules:($loadModules | sort | unique),
                masked_units:($maskedUnits | sort | unique),
                handoff:{to_stage:"host",
                  mechanism:$handoff.realization.mechanism,
                  completion_target:$handoff.realization.completion_unit.unit_name,
                  required_units:($handoff.realization.required_units
                    | map(.unit_name) | sort | unique),
                  preserved_mounts:($handoff.value.preserved_mounts
                    | unique_by([.initrd_path,.host_path])
                    | sort_by([.initrd_path,.host_path])),
                  durable_state_roots:($handoff.value.durable_state_roots
                    | unique_by([.initrd_path,.host_path])
                    | sort_by([.initrd_path,.host_path])),
                  transferable_handles:false,
                  receiving_stage_reauthorizes:true,
                  receiving_stage_reacquires:true}}' \
            > "$out/initrd-stage-contract.json.tmp"
          contract_size=$(stat -c %s "$out/initrd-stage-contract.json.tmp")
          [ "$contract_size" -gt 1 ]
          truncate -s $((contract_size - 1)) "$out/initrd-stage-contract.json.tmp"
          mv "$out/initrd-stage-contract.json.tmp" "$out/initrd-stage-contract.json"
          ln -s ${deploymentBundle} "$out/deployment"

          echo "==> $archive_size bytes written to $out/initrd.img"
        '';
      }
    ];

    meta = {
      description = "AOS initrd (zstd-compressed cpio, systemd PID 1)";
    };
  };
  storeRoot = value: let
    path = builtins.toString value;
    matched = builtins.match "(/nix/store/[0-9a-z]{32}-[^/]+)(/.*)?" path;
  in
    if matched == null
    then throw "initrd retained dependency must be a path in the Nix store"
    # Substring preserves the input's Nix dependency context.
    else builtins.substring 0 (builtins.stringLength (builtins.head matched)) path;
  retainedRoots = lib.unique (map storeRoot (
    [initrdArchive registration deploymentBundle kernelModuleTree]
    ++ map (entry: entry.store_path) dependencyRoots
  ));
  initrdArtifact = mkDerivation {
    name = "aos-initrd";
    src = null;
    buildDeps = [coreutils initrdArchive];
    allowedReferences = retainedRoots;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          ln -s ${initrdArchive}/initrd.img "$out/initrd.img"
          cp ${initrdArchive}/initrd-stage-contract.json "$out/initrd-stage-contract.json"
          ln -s ${deploymentBundle} "$out/deployment"

          # Every root is visible to Nix independently of archive compression.
          # Qualification checks exact direct references, including omissions.
          cat > "$out/reference-roots" <<'ROOTS'
          ${lib.concatStringsSep "\n" (map builtins.toString retainedRoots)}
          ROOTS
        '';
      }
    ];

    meta.description = "AOS initrd with explicit retained dependency roots";
  };
in
  initrdArtifact

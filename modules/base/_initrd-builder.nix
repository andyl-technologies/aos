##! modules/base/_initrd-builder.nix — Tier-ii systemd initrd builder
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
##!      lib/systemd/system/, not example/; generateUnits can't fold these
##!      in automatically for initrd — see the TODO in lib/modules/systemd/lib.nix:510.)
##!   8. The output of `generateUnits` for the rendered initrd units —
##!      `boot.initrd.systemd.services` etc. resolved through the stage-1
##!      ToUnit renderers.
##!
##! Arguments:
##!   pkgs          — AOS package set
##!   lib           — AOS library
##!   kernel        — kernel derivation (provides /lib/modules/<ver>/)
##!   loadModules — list of module names for /etc/modules-load.d/initrd.conf
##!   initrdUnits   — derivation whose output is the rendered
##!                   /etc/systemd/system directory (from generateUnits)
##!   initrdNetworkDir — derivation whose output is a directory of rendered
##!                   systemd-networkd `.network` files (from the typed
##!                   `boot.initrd.systemd.network` tree); copied into
##!                   /etc/systemd/network/. Null/absent ⇒ no networkd config.
##!
##! Output: $out/initrd.img (zstd-compressed newc cpio archive)
{
  pkgs,
  lib,
  kernel,
  loadModules,
  initrdUnits,
  initrdExtraPackages ? [],
  initrdNetworkDir ? null,
  maskedUnits ? [],
}: let
  inherit
    (pkgs)
    bash
    coreutils
    cpio
    cryptsetup
    e2fsprogs
    findutils
    gptfdisk
    grep
    iproute2
    kmod
    less
    systemd
    util-linux
    zstd
    ;

  # Packages whose full runtime closures are copied into the initrd's
  # /nix/store. See the docstring at the top of this file for why.
  initrdPackages =
    [
      bash
      coreutils
      cryptsetup
      e2fsprogs
      grep
      gptfdisk
      iproute2
      kmod
      less
      systemd
      util-linux
    ]
    # Feature-specific closures injected by modules (e.g. the measured-boot
    # PCR-policy public key — RFC-0006 phase 3).
    ++ initrdExtraPackages;

  # Short /bin/<name> symlinks. A binary only needs to appear here if an
  # initrd unit (or a script invoked by one) references it as `/bin/foo`
  # rather than as an absolute store path. Keep it conservative — the
  # store paths work anywhere.
  initrdBinaries = [
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
    "systemd-run-generator"
    "systemd-debug-generator"
  ];

  # Render the (pkg, binary, src) triples into `ln -sfn` invocations.
  binarySymlinks =
    lib.concatMapStringsSep "\n" (e: "ln -sfn ${e.pkg}/${e.src}/${e.bin} root/bin/${e.bin}")
    initrdBinaries;

  # Upstream unit symlinks go into /lib/systemd/system/ (not /etc/)
  # so that systemd.mask= on the kernel cmdline can override them.
  # Generators write masks to /run/systemd/generator/ which sits
  # between /etc/ (highest) and /lib/ (lowest) in systemd's unit
  # search priority.
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

  interactivePath = lib.concatStringsSep ":" (
    (map (p: "${p}/bin") initrdPackages)
    ++ (map (p: "${p}/sbin") initrdPackages)
    ++ ["/bin" "/sbin"]
  );
in
  pkgs.mkDerivation {
    name = "aos-initrd";
    src = null;

    buildDeps = [
      cpio
      zstd
      coreutils
      findutils
    ];

    # `exportReferencesGraph` writes one file per package/name pair
    # containing that package's transitive runtime closure. Nix
    # interleaves each store path with metadata (size, deriver,
    # references) — the `populate` phase greps for lines starting
    # with `/nix/store/` to recover the path list.
    #
    # `initrdUnits` is included so the `unit-<name>.service` store
    # paths that the rendered units symlink into land in the initrd's
    # /nix/store. Without it `/etc/systemd/system/*.service` resolves
    # to dangling symlinks and systemd emits "No such file or
    # directory" for each initrd service.
    exportReferencesGraph =
      lib.concatLists
      (lib.imap (i: p: ["closure-${toString i}" p]) initrdPackages)
      ++ [
        "closure-initrd-units"
        initrdUnits
      ];

    phases = [
      {
        name = "populate";
        script = ''
          set -euo pipefail

          echo "==> Assembling AOS systemd initrd"

          # ── 0. Extract unique store paths from the closure graph files ─
          grep -h '^/nix/store/' closure-* | sort -u > closure-paths
          echo "    $(wc -l < closure-paths) unique store paths in initrd closure"

          # ── 1. Directory skeleton ───────────────────────────────────────
          mkdir -p root/bin
          mkdir -p root/sbin
          mkdir -p root/etc/systemd/system
          mkdir -p root/etc/modules-load.d
          mkdir -p root/lib/systemd/system
          mkdir -p root/lib/systemd/system-generators
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
          if [ -d ${kernel}/lib/modules ]; then
            cp -a ${kernel}/lib/modules/. root/lib/modules/
          else
            echo "initrd-builder: ${kernel}/lib/modules not found" >&2
            exit 1
          fi

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

          # Make the interactive stage-1 recovery shells usable:
          cat > root/etc/profile <<PROFILE
          export PATH="${interactivePath}"
          export PAGER=less
          PROFILE

          # systemd-network (uid/gid 192, matching modules/base/users.nix):
          # systemd-networkd runs User=systemd-network and fails activation
          # with "unknown user" if it is absent.
          cat > root/etc/passwd <<'PASSWD'
          root:x:0:0:root:/root:/bin/bash
          systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
          nobody:x:65534:65534:Nobody:/:/sbin/nologin
          PASSWD

          cat > root/etc/group <<'GROUP'
          root:x:0:
          adm:x:4:
          tty:x:5:
          disk:x:6:
          lp:x:7:
          kmem:x:9:
          wheel:x:10:
          dialout:x:20:
          utmp:x:22:
          cdrom:x:24:
          clock:x:25:
          tape:x:26:
          audio:x:29:
          kvm:x:36:
          video:x:44:
          users:x:100:
          input:x:104:
          sgx:x:106:
          render:x:107:
          systemd-journal:x:190:
          systemd-network:x:192:
          nobody:x:65534:
          GROUP

          # /etc/hosts — localhost plus GCP's metadata.google.internal, which
          # is the one cloud metadata endpoint reached by name rather than IP
          # literal. No stage-1 DNS resolver, so this static map stands in.
          cat > root/etc/hosts <<'HOSTS'
          127.0.0.1 localhost
          ::1 localhost
          169.254.169.254 metadata.google.internal metadata
          HOSTS

          cat > root/etc/shadow <<'SHADOW'
          root:!*::0:99999:7:::
          SHADOW
          # The traditional 0000 shadow permission works because root (uid 0)
          # bypasses the check; but we cannot read back the file during cpio
          # packing without read bit set. Use 0600 — the archived file still
          # ends up owned by uid 0 thanks to `cpio -R +0:+0`.
          chmod 0600 root/etc/shadow

          cat > root/etc/machine-id <<'MACHINEID'
          MACHINEID

          # ── 6. Upstream systemd units and generators ───────────────────
          ${unitSymlinks}
          ${generatorSymlinks}

          # ── 7. Rendered initrd units from boot.initrd.systemd.* ────────
          # Matches generateUnits output — a directory whose entries are
          # unit files and dependency directories (*.wants, *.requires).
          if [ -d ${initrdUnits} ]; then
            cp -a ${initrdUnits}/. root/etc/systemd/system/ || true
          fi

          # ── 7a. Rendered networkd .network config from
          #    boot.initrd.systemd.network. These are config, not units, so
          #    they bypass generateUnits and land in /etc/systemd/network/.
          mkdir -p root/etc/systemd/network
          ${lib.optionalString (initrdNetworkDir != null) ''
            if [ -d ${initrdNetworkDir} ]; then
              cp -a ${initrdNetworkDir}/. root/etc/systemd/network/ || true
            fi
          ''}

          # ── 7c. Enable systemd-networkd-wait-online via network-online.target.
          #    [Install] sections of upstream units aren't realized in the
          #    initrd (generateUnits doesn't process upstreamUnits here), so
          #    this .wants symlink is what makes the gate's `systemctl start
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

          # ── 8. Trim: drop files that only exist in the store for build-
          #    time or developer use. Packages keep these on disk systemwide;
          #    this only removes them from the initrd's cpio. Nix's closure
          #    tracking already ran, so trimming inside the store-path copies
          #    doesn't affect the derivation's declared references.
          #
          #    Per-category rationale below. Each `find` is guarded with
          #    `-print0 | xargs -0 -r` (Nix sandbox has nullsafe xargs).
          echo "==> Trimming build-time and dev artifacts from initrd tree"

          # `cp -a` preserves the store's read-only permissions. The trim
          # steps below need write access to remove files; cpio later uses
          # -R +0:+0 to force uid/gid 0 regardless of file mode, so making
          # the copies writable here doesn't affect the archived perms.
          chmod -R u+w root/nix/store 2>/dev/null || true

          # glibc: headers, static archives, locale source files, gconv
          # modules for obscure encodings (keep UTF-8 / UNICODE / ISO-8859-*).
          find root/nix/store -maxdepth 2 -type d -name '*-glibc-*' -print0 \
            | xargs -0 -r -I{} sh -c '
                rm -rf "{}/include" "{}/share/i18n" "{}/var" "{}/share/doc" "{}/share/info"
                find "{}/lib" -maxdepth 1 -name "*.a" -delete 2>/dev/null
                # gconv: keep the frequently used converters, rm the rest.
                # systemd + bash + coreutils only ever hit UTF-8 / ANSI_X3.4 /
                # ISO-8859-1; other encodings are for i18n locale files we
                # are not shipping anyway.
                if [ -d "{}/lib/gconv" ]; then
                  find "{}/lib/gconv" -type f \( -name "*.so" -o -name "gconv-modules*" \) \
                    ! -name "UTF-8.so" ! -name "UTF-16.so" ! -name "UTF-32.so" \
                    ! -name "UNICODE.so" ! -name "ISO8859-1.so" ! -name "ISO8859-15.so" \
                    ! -name "ANSI_X3.110.so" ! -name "gconv-modules*" -delete 2>/dev/null
                fi
              ' _

          # systemd: huge kitchen sink. The initrd needs PID 1 (systemd
          # itself), systemd-udevd, fstab/cryptsetup/sysroot generators,
          # tmpfiles, and a handful of cgroup/journal helpers — nothing
          # else. Drop the long tail.
          find root/nix/store -maxdepth 2 -type d -name '*-systemd-*' -print0 \
            | xargs -0 -r -I{} sh -c '
                rm -rf "{}/lib/security" \
                       "{}/lib/systemd/boot" \
                       "{}/lib/systemd/catalog" \
                       "{}/lib/systemd/portable" \
                       "{}/lib/sysusers.d" \
                       "{}/lib/kernel" \
                       "{}/lib/udev/hwdb.d" \
                       "{}/lib/rpm" \
                       "{}/share/doc" "{}/share/man" "{}/share/info" \
                       "{}/share/factory" "{}/share/polkit-1" "{}/share/bash-completion" \
                       "{}/share/zsh" "{}/share/dbus-1" "{}/share/locale" \
                       "{}/include"
                # NSS plugins: keep libnss_resolve (systemd-resolved DNS
                # lookups) and libnss_myhostname (127.0.0.1/::1 → hostname).
                # Drop the dynamic-user ones — initrd has no user database.
                rm -f "{}/lib/libnss_systemd.so."* \
                      "{}/lib/libnss_mymachines.so."*
                # Keep: systemd (PID 1), systemd-udevd, systemd-journald,
                #       systemd-executor, systemd-networkd + systemd-resolved
                #       (metadata acquisition needs platform networking),
                #       systemd-fsck, shutdown, and the generator helpers
                #       invoked by the initrd units.
                # systemd-creds and systemd-cryptenroll are deliberately KEPT
                # (RFC-0006 phase 3): first-boot sealing of /var runs in the
                # initrd (aos-var-crypt, after aos-repart) and uses
                # systemd-cryptenroll --tpm2-*; the systemd-cryptsetup
                # TPM2-token unlock on later boots also runs here.
                # systemd-measure stays stripped: it is a build-time tool
                # (predicting PCR-11 for the registry catalog), not needed
                # inside the initrd. (No apostrophes in this comment — it
                # lives inside a single-quoted sh -c block.)
                # systemd-repart is kept because the
                # convention-substrate carves /var/swap/root-b in the initrd
                # before mount-var via repart.d drop-ins. systemd-firstboot
                # stays stripped (hostname is manifest-rendered, not firstboot).
                for tool in systemd-homed systemd-homework systemd-portabled \
                            systemd-nspawn systemd-importd systemd-pull \
                            systemd-firstboot systemd-confext \
                            systemd-sysext systemd-mountfsd systemd-nsresourced \
                            systemd-measure \
                            systemd-analyze systemd-run systemd-stdio-bridge \
                            systemd-vmspawn systemd-vpick systemd-ssh-generator \
                            systemd-ssh-proxy systemd-update-utmp bootctl \
                            coredumpctl hostnamectl localectl resolvectl \
                            timedatectl userdbctl kernel-install \
                            systemd-logind systemd-timesyncd \
                            systemd-journal-gatewayd systemd-journal-remote \
                            systemd-journal-upload systemd-oomd systemd-pstore \
                            systemd-boot systemd-coredump systemd-nsresourcework; do
                  rm -f "{}/bin/$tool" "{}/lib/systemd/$tool" \
                        "{}/lib/systemd/system-generators/$tool"
                done
              ' _

          # openssl: static archives (libcrypto.a / libssl.a) are dev-only,
          # c_rehash is a perl script, cmake/pkgconfig are dev metadata.
          find root/nix/store -maxdepth 2 -type d -name '*-openssl-*' -print0 \
            | xargs -0 -r -I{} sh -c '
                rm -rf "{}/lib/cmake" "{}/lib/pkgconfig" \
                       "{}/share/doc" "{}/share/man" \
                       "{}/include"
                find "{}/lib" -maxdepth 1 -name "*.a" -delete 2>/dev/null
                rm -f "{}/bin/c_rehash"
              ' _

          # ukify + its Python dependency closure: only needed at image-
          # build time to assemble the UKI, never in the initrd. Since
          # ukify's shebang references python3 directly, the systemd
          # closure drags in python3-3.14 (~200 MiB), pefile, and
          # pyelftools.
          rm -f root/nix/store/*-systemd-*/bin/ukify \
                root/nix/store/*-systemd-*/bin/.ukify-unwrapped \
                root/nix/store/*-systemd-*/lib/systemd/ukify
          rm -rf root/nix/store/*-python3-3.* \
                 root/nix/store/*-python3-pefile-* \
                 root/nix/store/*-python3-pyelftools-*

          # Bootstrap toolchain leftovers — intermediate gcc/binutils/
          # glibc/coreutils versions used to build the current stdenv
          # but referenced only via embedded debug paths and old
          # RPATHs. Nothing in the initrd actually exec's them: the
          # runtime binaries resolve glibc through their current
          # $out/lib RPATH. Purge aggressively — reclaims roughly
          # 1 GiB of uncompressed tmpfs footprint, which is what
          # makes the initramfs extract fit inside a 2 GiB VM.
          #
          # Keep: the currently-linked glibc-2.39 (runtime for
          # everything in the initrd), and all the gcc-wrapped
          # paths that chain to it.
          rm -rf root/nix/store/*-gcc-3.*  \
                 root/nix/store/*-gcc-4.*  \
                 root/nix/store/*-gcc-8.*  \
                 root/nix/store/*-gcc-11.* \
                 root/nix/store/*-gcc-14.3.0-stage2 \
                 root/nix/store/*-gcc-14.3.0-wrapped \
                 root/nix/store/*-binutils-2.20* \
                 root/nix/store/*-binutils-2.25* \
                 root/nix/store/*-binutils-2.30* \
                 root/nix/store/*-binutils-2.41* \
                 root/nix/store/*-glibc-2.12 \
                 root/nix/store/*-glibc-2.2.5 \
                 root/nix/store/*-coreutils-8.32 \
                 root/nix/store/*-bash-4.2 \
                 root/nix/store/*-linux-headers-2.6.* \
                 root/nix/store/*-source

          # util-linux: man pages, zsh completion, etc.
          find root/nix/store -maxdepth 2 -type d -name '*-util-linux-*' -print0 \
            | xargs -0 -r -I{} sh -c '
                rm -rf "{}/share/man" "{}/share/doc" "{}/share/bash-completion" "{}/include"
              ' _

          # Everything else: kill shared doc/man/info/include. These are
          # developer artifacts with zero runtime use.
          find root/nix/store -maxdepth 3 -type d \( -name man -o -name info -o -name doc -o -name include \) \
            ! -path 'root/nix/store/*/lib/systemd/*' -print0 \
            | xargs -0 -r rm -rf
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

          echo "==> $(stat -c '%s bytes' $out/initrd.img) written to $out/initrd.img"
        '';
      }
    ];

    meta = {
      description = "AOS initrd (zstd-compressed cpio, systemd PID 1)";
    };
  }

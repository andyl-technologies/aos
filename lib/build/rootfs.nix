##! lib/build/rootfs.nix — shared rootfs population + ext4 image builder
##!
##! Produces a populated rootfs tree and an ext4 image of it. Does NOT
##! assemble partitions — the caller composes boot/var/metadata partitions
##! around the returned root.img.
##!
##! The layout is merged-usr:
##!
##!     /usr/{bin,sbin,lib}   — real directories
##!     /{bin,sbin,lib}       — symlinks into /usr/
##!
##! Every file in the resulting image is owned by uid/gid 0: `mkfs.ext4 -d`
##! runs under `fakeroot` so the sandbox user's uid doesn't leak into the
##! image (auditd and several other daemons refuse to start when their
##! config files are not root-owned).
##!
##! Arguments:
##!   pkgs                 — AOS package set
##!   lib                  — AOS library
##!   system               — evaluated AOS system (provides toplevel + kernel)
##!   pname                — derivation name prefix (default "aos-rootfs")
##!   label                — filesystem label (default "aos-root")
##!   etcTarget            — "etc" (production) or "etc.lower" (overlay-lower
##!                          for VM tests). The toplevel's /etc is copied
##!                          into rootfs/${etcTarget}/.
##!   unwrapStoreSymlinks  — recursively replace /nix/store symlinks inside
##!                          etcTarget with copies. Needed when etcTarget is
##!                          "etc.lower" and postPopulate writes into it.
##!   shrinkToFit          — resize2fs -M + grow by `headroomMiB` (production
##!                          image). false leaves the image at an over-
##!                          provisioned initial size (VM test disk).
##!   headroomMiB          — extra free space above shrunk fs (default 64).
##!   minSizeMiB           — floor on the initial mkfs size (default 512).
##!                          Useful for test images that get written to
##!                          during VM execution.
##!   extraClosures        — derivations whose full closures land in
##!                          /nix/store. toplevel + kernel are always added.
##!   symlinkFarmPkgs      — derivations whose bin/sbin/libexec entries get
##!                          symlinked into /usr/bin, /usr/sbin, /usr/libexec.
##!                          Later entries never overwrite earlier ones.
##!   postPopulate         — shell fragment spliced after tree population and
##!                          before mkfs. Runs with `rootfs/` as the tree and
##!                          `$ETC_TARGET` as the etc-path basename.
##!
##! Output: `$out/root.img` (the ext4 image) and `$out/rootfs-size-bytes`
##! (the final image byte count, so the caller can size the partition).
{
  pkgs,
  lib,
  system,
  pname ? "aos-rootfs",
  label ? "aos-root",
  etcTarget ? "etc",
  unwrapStoreSymlinks ? false,
  shrinkToFit ? true,
  headroomMiB ? 64,
  minSizeMiB ? 512,
  extraClosures ? [],
  symlinkFarmPkgs ? [],
  postPopulate ? "",
}: let
  toplevel = system.config.system.build.toplevel;
  kernel = system.config.system.build.kernel;

  # Full set of closures to merge. toplevel carries stage-2 systemd's
  # closure; kernel carries /lib/modules targets. Callers add more when
  # the running rootfs references store paths the closure reachability
  # scanner wouldn't otherwise catch (e.g. the VM agent shell script
  # referencing `/nix/store/...-socat-*` verbatim).
  allClosures = [toplevel kernel] ++ extraClosures;

  # Pair each closure with a numeric label for exportReferencesGraph.
  # The populate phase greps `closure-*` and sorts -u for unique paths.
  closureGraph =
    lib.concatLists
    (lib.imap (i: p: ["closure-${toString i}" p]) allClosures);

  # Symlink-farm script fragment — one block per package. Ordering
  # matters (earlier wins); callers list higher-priority packages first.
  symlinkFarmScript =
    lib.concatMapStringsSep "\n" (pkg: ''
      if [ -d "${pkg}/bin" ]; then
        for bin in "${pkg}/bin/"*; do
          n=$(basename "$bin")
          [ -e "rootfs/usr/bin/$n" ] || ln -sfn "$bin" "rootfs/usr/bin/$n"
        done
      fi
      if [ -d "${pkg}/sbin" ]; then
        for bin in "${pkg}/sbin/"*; do
          n=$(basename "$bin")
          [ -e "rootfs/usr/sbin/$n" ] || ln -sfn "$bin" "rootfs/usr/sbin/$n"
        done
      fi
      if [ -d "${pkg}/libexec" ]; then
        mkdir -p rootfs/usr/libexec
        for bin in "${pkg}/libexec/"*; do
          n=$(basename "$bin")
          [ -e "rootfs/usr/libexec/$n" ] || ln -sfn "$bin" "rootfs/usr/libexec/$n"
        done
      fi
    '')
    symlinkFarmPkgs;

  unwrapScript = lib.optionalString unwrapStoreSymlinks ''
    # Toplevel /etc can contain symlinks pointing into the read-only
    # /nix/store (e.g. /etc/systemd/system → a system-units derivation).
    # Replace each such link with a copy of its target so subsequent
    # writes into the tree don't fail with EACCES. Replacing a
    # directory-symlink can reveal new store symlinks in the copied
    # subtree — loop until no store symlinks remain.
    while true; do
      find rootfs/"$ETC_TARGET" -type l | while IFS= read -r link; do
        target=$(readlink "$link")
        case "$target" in
          /nix/store/*)
            rm "$link"
            cp -a "$target" "$link"
            ;;
        esac
      done
      if ! find rootfs/"$ETC_TARGET" -type l -exec readlink {} \; \
           | grep -q '^/nix/store/'; then
        break
      fi
      chmod -R u+w rootfs/"$ETC_TARGET"
    done
    chmod -R u+w rootfs/"$ETC_TARGET"
  '';
in
  pkgs.mkDerivation {
    inherit pname;
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.tar
      pkgs.e2fsprogs
      pkgs.fakeroot
      pkgs.util-linux
    ];

    exportReferencesGraph = closureGraph;

    TOPLEVEL = toString toplevel;
    KERNEL = toString kernel;
    SYSTEMD = toString pkgs.systemd;
    COREUTILS = toString pkgs.coreutils;
    ETC_TARGET = etcTarget;
    # `$BASH` is a bash built-in pointing at the bash executable
    # currently running the script — setting it as a derivation env
    # var has no effect at runtime. Use a dedicated name (AOS_BASH)
    # so the ln -sfn targets resolve to the package directory, not
    # to the already-executable path.
    AOS_BASH = toString pkgs.bash;

    phases = [
      {
        name = "populate";
        script = ''
          set -eu

          # ── 0. Extract unique store paths from all closure graph files ──
          grep -h '^/nix/store/' closure-* | sort -u > store-paths
          echo "==> Populating rootfs ($(wc -l < store-paths) store paths)"

          # ── 1. Directory skeleton (merged-usr) ──────────────────────────
          # Full /usr merge AND /usr/sbin → /usr/bin merge. systemd's
          # unmerged-bin taint fires when /usr/sbin isn't a symlink
          # into /usr/bin (see src/core/taint.c's test_usr_unmerged).
          #
          # The image's Nix closure lives at /nix.lower/store; /nix is an
          # empty mountpoint where nix-overlay-setup.service stacks an
          # overlayfs in the initrd (lowerdir=/nix.lower, upperdir on the
          # /var partition). At runtime, /nix/store/... and /nix.lower/store/...
          # both resolve to the closure — the former through the overlay
          # (matching the path embedded in every binary's RUNPATH and
          # shebang), the latter directly on disk for inspection.
          mkdir -p rootfs/nix.lower/store
          mkdir -p rootfs/nix
          mkdir -p rootfs/usr/bin rootfs/usr/lib
          ln -sfn bin rootfs/usr/sbin
          ln -sfn usr/bin rootfs/bin
          ln -sfn usr/bin rootfs/sbin
          ln -sfn usr/lib rootfs/lib
          mkdir -p rootfs/"$ETC_TARGET"
          mkdir -p rootfs/proc rootfs/sys rootfs/dev rootfs/tmp
          mkdir -p rootfs/run rootfs/var rootfs/sysroot
          mkdir -p rootfs/var/{log,lib,tmp}
          # /boot + /var are mountpoints that modules/base/filesystems.nix
          # writes into /etc/fstab (ESP → /boot, var partition → /var).
          # systemd-fstab-generator synthesises boot.mount / var.mount
          # from those entries; if the mountpoint directory doesn't
          # exist, the mount fails at stage-2 boot. /var was already
          # above — /boot would otherwise be missing in production.
          mkdir -p rootfs/boot
          mkdir -m 0700 rootfs/root
          mkdir -p rootfs/run/current-system

          # ── 2. Copy the closure into /nix/store ─────────────────────────
          total=$(wc -l < store-paths)
          count=0
          while IFS= read -r p; do
            count=$((count + 1))
            if [ $((count % 50)) -eq 0 ] || [ "$count" -eq "$total" ]; then
              printf '\r    [%d/%d]' "$count" "$total"
            fi
            if [ -e "$p" ]; then
              cp -a "$p" rootfs/nix.lower/store/
            else
              echo ""
              echo "    WARN: store path does not exist: $p" >&2
            fi
          done < store-paths
          echo ""

          # ── 3. PID 1 and compat symlinks ────────────────────────────────
          # /sbin/init (via merged-usr: /sbin → usr/bin) → systemd.
          ln -sfn "$SYSTEMD/lib/systemd/systemd" rootfs/usr/bin/init
          ln -sfn "$AOS_BASH/bin/bash" rootfs/usr/bin/bash
          ln -sfn "$AOS_BASH/bin/sh" rootfs/usr/bin/sh
          ln -sfn "$COREUTILS/bin/env" rootfs/usr/bin/env

          # ── 4. Kernel modules ───────────────────────────────────────────
          # kmod looks up modules at /lib/modules/$(uname -r); the
          # /lib → usr/lib symlink makes this resolve to usr/lib/modules.
          ln -sfn "$KERNEL/lib/modules" rootfs/usr/lib/modules

          # ── 5. /var/run → /run ──────────────────────────────────────────
          # Modern-Linux convention: /run is tmpfs, /var/run is a back-
          # compat symlink. Many daemons still reference /var/run paths.
          ln -sfn /run rootfs/var/run

          # ── 6. /run/current-system → toplevel ───────────────────────────
          ln -sfn "$TOPLEVEL" rootfs/run/current-system

          # ── 7. Copy toplevel's /etc into rootfs/$ETC_TARGET ─────────────
          # tar-pipe rather than `cp -a` so extracted files inherit the
          # builder's umask (writable) instead of the store's read-only
          # perms — subsequent writes from postPopulate need `u+w`.
          if [ -d "$TOPLEVEL/etc" ]; then
            echo "    Merging toplevel /etc into rootfs/$ETC_TARGET"
            (cd "$TOPLEVEL/etc" && tar cf - .) \
              | (cd rootfs/"$ETC_TARGET" && tar xf -)
            chmod -R u+w rootfs/"$ETC_TARGET"
          fi

          # ── 8. Unwrap /nix/store symlinks inside $ETC_TARGET ────────────
          ${unwrapScript}

          # ── 9. Empty machine-id — signals systemd to generate one ──────
          touch rootfs/"$ETC_TARGET"/machine-id

          # ── 10. Symlink farm for caller-supplied packages ───────────────
          ${symlinkFarmScript}

          # ── 11. Caller-supplied postPopulate hook ───────────────────────
          ${postPopulate}
        '';
      }
      {
        name = "mkfs";
        script = ''
          set -eu

          # Measure the populated tree. `du --apparent-size` is what
          # matters for mkfs.ext4 -d because it does NOT preserve
          # hardlinks (each hardlinked file becomes a separate copy).
          apparent_kb=$(du -sk --apparent-size rootfs | cut -f1)
          apparent_mib=$(( apparent_kb / 1024 ))
          echo "==> rootfs apparent size: ''${apparent_mib} MiB"

          # Over-provision during mkfs to allow the ext4 journal, inode
          # table, and tree metadata to land alongside the data.
          initial_mib=$(( apparent_mib * 3 / 2 + 256 ))
          if [ "$initial_mib" -lt ${toString minSizeMiB} ]; then
            initial_mib=${toString minSizeMiB}
          fi

          # fakeroot makes every file in rootfs appear as uid/gid 0
          # to mkfs.ext4, so the resulting image has root-owned files.
          # Without this, daemons fail ownership checks (auditd refuses
          # to start if /etc/audit/auditd.conf isn't owned by root).
          fakeroot -- mkfs.ext4 -d rootfs -L ${label} -m 1 -q \
            root.img "''${initial_mib}M"

          ${lib.optionalString shrinkToFit ''
            # Shrink to minimum, then grow by headroom + 1 MiB alignment.
            e2fsck -f -y root.img >/dev/null
            resize2fs -M root.img >/dev/null 2>&1
            blk_size=$(dumpe2fs -h root.img 2>/dev/null \
                         | awk '/Block size:/{print $3}')
            min_blocks=$(dumpe2fs -h root.img 2>/dev/null \
                           | awk '/Block count:/{print $3}')
            headroom_blocks=$(( ${toString headroomMiB} * 1048576 / blk_size ))
            final_blocks=$(( min_blocks + headroom_blocks ))
            resize2fs root.img "$final_blocks" >/dev/null 2>&1
            final_bytes=$(( final_blocks * blk_size ))
            final_bytes=$(( ((final_bytes + 1048575) / 1048576) * 1048576 ))
            truncate -s "$final_bytes" root.img
            echo "==> root.img: $(( final_bytes / 1048576 )) MiB (shrunk+headroom)"
          ''}
          ${lib.optionalString (!shrinkToFit) ''
            final_bytes=$(stat -c %s root.img)
            echo "==> root.img: $(( final_bytes / 1048576 )) MiB (unshrunk)"
          ''}
          echo "$final_bytes" > rootfs-size-bytes
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out
          mv root.img $out/root.img
          mv rootfs-size-bytes $out/rootfs-size-bytes
        '';
      }
    ];

    meta = {
      description = "AOS rootfs + ext4 image builder";
    };
  }

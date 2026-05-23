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
##! /etc is an empty mountpoint (the runtime overlay mounts on top in
##! stage-1); /run/etc is also an empty mountpoint
##! (run-etc-setup.service mounts a tmpfs there). The seed pointer
##! at `/aos-toplevel` is what aos-seed-profiles.service reads on
##! first boot to populate apm's profile state, breaking the
##! initrd→toplevel→initrd derivation cycle that direct interpolation
##! of `${config.system.build.toplevel}` in initrd service scripts
##! would create.
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
##!                          before mkfs. Runs with `rootfs/` as the tree.
##!
##! Output: `$out/root.img` (the ext4 image) and `$out/rootfs-size-bytes`
##! (the final image byte count, so the caller can size the partition).
{
  pkgs,
  lib,
  system,
  pname ? "aos-rootfs",
  label ? "aos-root",
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
          # /etc is an empty mountpoint — the runtime overlay (system
          # EROFS lower + per-gen ignition lower + /var/etc) mounts
          # on top in stage-1 (etc-overlay-setup.service).
          mkdir -p rootfs/etc
          mkdir -p rootfs/proc rootfs/sys rootfs/dev rootfs/tmp
          mkdir -p rootfs/run rootfs/var rootfs/sysroot
          mkdir -p rootfs/var/{log,lib,tmp}
          # /run/etc is an empty mountpoint — run-etc-setup.service
          # mounts a tmpfs there early in stage-1 so ignition-files
          # and etc-overlay-setup can stage per-gen state under it.
          mkdir -p rootfs/run/etc
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

          # ── 7. /aos-toplevel seed pointer ──────────────────────────────
          # First-boot bootstrap: aos-seed-profiles.service reads this
          # symlink to populate /var/lib/profiles/system/gen-1/toplevel
          # without referencing config.system.build.toplevel directly
          # (which would create an initrd→toplevel→initrd cycle). The
          # rootfs already references the toplevel via /nix.lower/store,
          # so adding the symlink doesn't introduce a new derivation
          # edge. See spec v12 §6.1.
          ln -sfn "$TOPLEVEL" rootfs/aos-toplevel

          # /etc/machine-id no longer touched here — stage-1's
          # aos-machine-id.service generates /var/etc/machine-id on
          # first boot from /proc/sys/kernel/random/uuid, and the
          # /var/etc lower of the overlay surfaces it at
          # /etc/machine-id. Doing it in the rootfs would land the
          # file on the wrong side of the overlay (and on every
          # rebuild's $TOPLEVEL, defeating per-host persistence).

          # ── 8. Symlink farm for caller-supplied packages ───────────────
          ${symlinkFarmScript}

          # ── 9. Caller-supplied postPopulate hook ───────────────────────
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

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
##!   erofsCompressionLevel — zstd level for EROFS images (default 19).
##!                           Test variants may select a faster level without
##!                           weakening production image compression.
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
  # Root filesystem type for the produced image. "ext4" (default) builds a
  # writable image via `mkfs.ext4 -d` (used by VM tests that write to root).
  # "erofs" builds a zstd-compressed, read-only image via `mkfs.erofs` —
  # roughly a third the size — for the immutable production boot image.
  fsType ? "ext4",
  erofsCompressionLevel ? 19,
  # When true, format a deterministic dm-verity Merkle hash tree
  # over the finalized root.img and emit `root.verity` + `root.roothash`
  # (+ `root.roothash.p7s` when an SB db key is supplied) + `root-verity-size-
  # bytes` alongside `root.img`. Default false leaves the erofs/ext4 path
  # byte-identical (every addition below is gated on this flag), so existing
  # ext4/VM-test images are unchanged. Only valid for the read-only `erofs`
  # path (an ext4 root is mutated at runtime, breaking the root hash).
  verity ? false,
  # Optional SB db key/cert (PEM). When supplied alongside `verity`, the
  # ASCII-hex root hash is PKCS#7-signed (Linux verifies the signature over the
  # hex string, not decoded bytes) so the in-kernel roothash-signature
  # enforcement path can validate it. Keys are a deployment overlay — the base
  # image stays key-free and reproducible (the roothash anchoring itself is
  # key-independent).
  secureBootKey ? null,
  secureBootCert ? null,
}: let
  toplevel = system.config.system.build.toplevel;
  kernel = system.config.system.build.kernel;

  # Deterministic dm-verity salt + superblock UUID, derived from the image
  # identity (mirrors lib/build/package-root-image.nix's pinned-salt/uuid
  # recipe) so the hash tree — and therefore the root hash baked into the
  # measured UKI cmdline — is reproducible across builds. The erofs root is
  # already byte-reproducible (mkfs.erofs --all-root -T0 -U <fixed>), so the
  # Merkle tree over its bytes is a deterministic function of pinned salt/uuid.
  mkUuid = seed: let
    h = builtins.hashString "sha256" seed;
  in "${builtins.substring 0 8 h}-${builtins.substring 8 4 h}-4${builtins.substring 13 3 h}-8${builtins.substring 17 3 h}-${builtins.substring 20 12 h}";
  verityUuid = mkUuid "aos-rootfs:verity:${pname}:${label}";
  veritySalt = builtins.substring 0 64 (builtins.hashString "sha256" "aos-rootfs:salt:${pname}:${label}");
  signVerity = verity && secureBootKey != null;

  # Full set of closures to merge. toplevel carries stage-2 systemd's
  # closure; kernel carries /lib/modules targets. Callers add more when
  # the running rootfs references store paths the closure reachability
  # scanner wouldn't otherwise catch (e.g. the VM agent shell script
  # referencing `/nix/store/...-socat-*` verbatim).
  allClosures = [toplevel kernel] ++ extraClosures;

  regInfo = import ./closure-info.nix {inherit pkgs lib;} {
    rootPaths = allClosures;
  };

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
  pkgs.mkDerivation ({
      inherit pname;
      version = "0";
      src = null;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.findutils
          pkgs.tar
          pkgs.e2fsprogs
          pkgs.fakeroot
          pkgs.util-linux
          pkgs.erofs-utils
        ]
        # Verity sub-step tooling is gated so the non-verity path's
        # build environment (and thus its derivation hash) is unchanged.
        ++ lib.optionals verity [
          pkgs.cryptsetup
          pkgs.openssl
          pkgs.gawk
          pkgs.grep
        ];

      exportReferencesGraph = closureGraph;

      TOPLEVEL = toString toplevel;
      KERNEL = toString kernel;
      REGINFO = toString regInfo;
      SYSTEMD_PRESETS = toString system.config.system.build.systemdSystemPresets;
      SYSTEMD = toString pkgs.systemd;
      COREUTILS = toString pkgs.coreutils;
      # `$BASH` is a bash built-in pointing at the bash executable
      # currently running the script — setting it as a derivation env
      # var has no effect at runtime. Use a dedicated name (AOS_BASH)
      # so the ln -sfn targets resolve to the package directory, not
      # to the already-executable path.
      AOS_BASH = toString pkgs.bash;

      phases =
        [
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
              mkdir -p rootfs/usr/lib/systemd/system-preset
              ln -sfn bin rootfs/usr/sbin
              ln -sfn usr/bin rootfs/bin
              ln -sfn usr/bin rootfs/sbin
              ln -sfn usr/lib rootfs/lib
              # /etc is an empty mountpoint — the runtime overlay (system
              # EROFS lower + per-gen config lower + /var/etc) mounts
              # on top in stage-1 (etc-overlay-setup.service).
              mkdir -p rootfs/etc
              mkdir -p rootfs/proc rootfs/sys rootfs/dev rootfs/tmp
              mkdir -p rootfs/run rootfs/var rootfs/sysroot
              mkdir -p rootfs/var/{log,lib,tmp}
              # /run/etc is an empty mountpoint — run-etc-setup.service
              # mounts a tmpfs there early in stage-1 so the metadata/config
              # pipeline and etc-overlay-setup can stage per-gen state under it.
              mkdir -p rootfs/run/etc
              # /boot + /var are mountpoints that modules/base/filesystems.nix
              # writes into /etc/fstab (ESP → /boot, var partition → /var).
              # systemd-fstab-generator synthesises boot.mount / var.mount
              # from those entries; if the mountpoint directory doesn't
              # exist, the mount fails at stage-2 boot. /var was already
              # above — /boot would otherwise be missing in production.
              mkdir -p rootfs/boot
              mkdir -m 0700 rootfs/root
              # Root-owned APM authoring config lives on the read-only rootfs,
              # so create it here instead of asking tmpfiles to mutate /root at
              # boot.
              mkdir -p rootfs/root/.config/apm/registries.d
              chmod 0700 rootfs/root/.config
              chmod 0755 rootfs/root/.config/apm
              chmod 0755 rootfs/root/.config/apm/registries.d
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

              # ── 6. Systemd preset policy ────────────────────────────────────
              cp -a "$SYSTEMD_PRESETS"/. rootfs/usr/lib/systemd/system-preset/

              # ── 7. /run/current-system → toplevel ───────────────────────────
              ln -sfn "$TOPLEVEL" rootfs/run/current-system

              # ── 8. /aos-toplevel seed pointer ──────────────────────────────
              # First-boot bootstrap: aos-seed-profiles.service reads this
              # symlink to populate /var/lib/profiles/system/gen-1/toplevel
              # without referencing config.system.build.toplevel directly
              # (which would create an initrd→toplevel→initrd cycle). The
              # rootfs already references the toplevel via /nix.lower/store,
              # so adding the symlink doesn't introduce a new derivation
              # edge. See spec v12 §6.1.
              ln -sfn "$TOPLEVEL" rootfs/aos-toplevel

              # ── 9. /aos-registration Nix DB seed ───────────────────────────
              # Stage-2 loads this plain text `nix-store --load-db` stream to
              # register the image closure without canonicalising/chowning store
              # contents. Copy the bytes instead of symlinking the derivation.
              cp "$REGINFO/registration" rootfs/aos-registration

              # /etc/machine-id no longer touched here — stage-1's
              # aos-machine-id.service generates /var/etc/machine-id on
              # first boot from /proc/sys/kernel/random/uuid, and the
              # /var/etc lower of the overlay surfaces it at
              # /etc/machine-id. Doing it in the rootfs would land the
              # file on the wrong side of the overlay (and on every
              # rebuild's $TOPLEVEL, defeating per-host persistence).

              # ── 10. Symlink farm for caller-supplied packages ───────────────
              ${symlinkFarmScript}

              # ── 11. Caller-supplied postPopulate hook ──────────────────────
              ${postPopulate}
            '';
          }
          {
            name = "mkfs";
            script =
              if fsType == "erofs"
              then ''
                set -eu

                # Read-only, zstd-compressed root for the immutable production
                # image. --all-root forces every file to uid/gid 0 (matching the
                # ext4 path's fakeroot, so ownership-sensitive daemons start); the
                # default xattr tolerance preserves SELinux labels; -T0 fixes
                # timestamps and -U pins the UUID for a reproducible image. EROFS is
                # content-sized, so there is no over-provisioning, journal, or
                # shrink step.
                #
                # Compression tuning (measured on the server closure):
                #   * -C262144 — 256 KiB compression cluster. The 4 KiB default is
                #     far too small for zstd to find context; 256 KiB is the knee of
                #     the size/read-amplification curve for a RAM-ample, read-mostly
                #     server root (a cold page fault decompresses one 256 KiB cluster;
                #     the hot path is served from the page cache regardless).
                #   * -Efragments,ztailpacking — packs the many small-file tails the
                #     /nix store is full of into shared fragment blocks / inode
                #     metadata. The single biggest win (~18 MiB) and, unlike a bigger
                #     cluster, it adds no read amplification.
                # Together: ~200 MiB (plain zstd-19) -> ~160 MiB. (Block dedupe was
                # measured at 0 bytes saved — nix store paths are content-addressed.)
                #
                # --workers parallelizes the otherwise single-threaded zstd-19
                # compression (hours on one core for the whole server closure).
                # erofs-utils splits the input into fixed 16 MiB segments and
                # reaps them in deterministic on-disk order, so the image stays
                # bit-reproducible regardless of the worker count — verified
                # identical across worker counts and against the single-threaded
                # build. $NIX_BUILD_CORES is the sandbox's core allotment.
                #
                # libgcc_s.so.1 must be loadable at runtime: glibc lazily
                # dlopen()s it for worker-thread teardown unwinding, and a
                # DT_RUNPATH on the binary doesn't satisfy a libc-initiated
                # dlopen — so point LD_LIBRARY_PATH at gcc-libs (same approach
                # as the kernel build in pkgs/kernel/linux.nix). Without it
                # mkfs prints "libgcc_s.so.1 must be installed for pthread_exit
                # to work" and risks aborting a worker.
                export LD_LIBRARY_PATH="${pkgs.gcc-libs}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
                mkfs.erofs --all-root -T0 \
                  -U bdfb6fc9-0000-4000-8000-000000000001 \
                  --workers="$NIX_BUILD_CORES" \
                  -z zstd,level=${toString erofsCompressionLevel} \
                  -C262144 \
                  -Efragments,ztailpacking \
                  -L ${label} root.img rootfs
                fsck.erofs root.img >/dev/null
                final_bytes=$(stat -c %s root.img)
                echo "==> root.img: $(( final_bytes / 1048576 )) MiB (erofs zstd-${toString erofsCompressionLevel}, 256K cluster, fragments)"
                echo "$final_bytes" > rootfs-size-bytes
              ''
              else ''
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
        ]
        # Build a deterministic dm-verity hash tree over the finalized
        # root.img. Gated, so the phase list (and the derivation) is unchanged
        # when verity = false. Mirrors lib/build/package-root-image.nix's
        # `veritysetup format --salt <pinned> --uuid <pinned>` + roothash
        # extraction + optional `openssl cms -sign` recipe. erofs needs no
        # shrink/normalize step — it is content-sized and already -T0 -U fixed,
        # so the tree is over stable bytes.
        ++ lib.optional verity {
          name = "verity";
          script = ''
            set -eu

            veritysetup format --salt "$VERITY_SALT" --uuid "$VERITY_UUID" \
              root.img root.verity > veritysetup.out
            root_hash=$(
              gawk -F: '/Root hash:/ {
                gsub(/^[ \t]+/, "", $2);
                print $2
              }' veritysetup.out
            )
            if ! printf '%s' "$root_hash" | grep -Eq '^[0-9a-f]{64}$'; then
              echo "invalid dm-verity root hash: $root_hash" >&2
              exit 1
            fi

            # Linux verifies the PKCS#7 over the ASCII-hex root hash string, not the
            # decoded hash bytes; dm-verity passes argv as the hex string to
            # verify_pkcs7_signature.
            printf '%s' "$root_hash" > root.roothash
            if [ -n "''${SIGN_VERITY:-}" ]; then
              openssl cms -sign -binary \
                -in root.roothash \
                -signer "$ROOT_HASH_CERT" \
                -inkey "$ROOT_HASH_KEY" \
                -outform DER \
                -out root.roothash.p7s \
                -nosmimecap \
                -noattr
              openssl cms -verify -binary \
                -inform DER \
                -in root.roothash.p7s \
                -content root.roothash \
                -CAfile "$ROOT_HASH_CERT" \
                -out /dev/null
            else
              # Key-free base image: no detached signature. The roothash-on-cmdline
              # anchoring (PCR 11 + db Authenticode over the whole UKI) is
              # key-independent and is what binds the root; the .p7s is only for the
              # optional in-kernel roothash-signature enforcement path.
              : > root.roothash.p7s
            fi

            veritysetup verify root.img root.verity "$root_hash"
            stat -c %s root.verity > root-verity-size-bytes
            echo "==> dm-verity roothash: $root_hash ($(stat -c %s root.verity) byte hash tree)"
          '';
        }
        ++ [
          {
            name = "install";
            # Concatenate the gated verity moves rather than interpolating inline,
            # so the non-verity script is byte-identical (empty append) — the
            # rootfs derivation for ext4/erofs systems is unchanged.
            script =
              ''
                mkdir -p $out
                mv root.img $out/root.img
                mv rootfs-size-bytes $out/rootfs-size-bytes
              ''
              + lib.optionalString verity ''
                mv root.verity $out/root.verity
                mv root.roothash $out/root.roothash
                mv root.roothash.p7s $out/root.roothash.p7s
                mv root-verity-size-bytes $out/root-verity-size-bytes
              '';
          }
        ];

      meta = {
        description = "AOS rootfs + ext4 image builder";
      };
    }
    // lib.optionalAttrs verity {
      # Verity env (gated): present only on the verity path so the non-verity
      # derivation's environment — and hash — is unchanged.
      VERITY_SALT = veritySalt;
      VERITY_UUID = verityUuid;
      SIGN_VERITY =
        if signVerity
        then "1"
        else "";
      ROOT_HASH_KEY =
        if signVerity
        then toString secureBootKey
        else "";
      ROOT_HASH_CERT =
        if signVerity
        then toString secureBootCert
        else "";
    })

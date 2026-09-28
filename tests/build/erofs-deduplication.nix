# Measure an already-realized labeled EROFS cohort without rebuilding its
# packages. For the Host fixture, invoke through aos-dev with --argstr
# erofsBaselineRoot pointing to the exact original rootfs output. The result
# is packing/preservation evidence, not image publication or VM qualification.
{pkgs}: {erofsBaselineRoot}: let
  baselineRootfs = builtins.storePath erofsBaselineRoot;
  policySupport = ../../pkgs/security/_aos-selinux-production-policy;
in
  pkgs.mkDerivation {
    pname = "erofs-deduplication-measurement";
    version = "1";
    src = null;

    buildDeps = [
      baselineRootfs
      pkgs.coreutils
      pkgs.diffutils
      pkgs.erofs-utils
      pkgs.python3
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "check";
        script = ''
          set -eu
          export LC_ALL=C TZ=UTC

          cp ${./verify-erofs-repack.py} verify-erofs-repack.py
          cp ${./verify-erofs-repack_test.py} verify-erofs-repack_test.py
          ${pkgs.python3}/bin/python3 -B verify-erofs-repack_test.py
          test -s ${baselineRootfs}/root.img
          test -s ${baselineRootfs}/rootfs-selinux-contexts.json

          # The pinned reader preserves original hardlinks and permissions.
          # Reuse the production PAX encoder instead of experimental rebuild
          # mode, which cannot import compressed input files in erofs-utils
          # 1.9.4. Every byte and exact planned label enters this one output.
          ${pkgs.erofs-utils}/bin/fsck.erofs \
            --extract=baseline --preserve-perms ${baselineRootfs}/root.img
          ${pkgs.python3}/bin/python3 -B ${policySupport}/labeled_erofs_tar.py \
            --root baseline \
            --map ${baselineRootfs}/rootfs-selinux-contexts.json \
            --output baseline-labeled.tar
          ${pkgs.erofs-utils}/bin/mkfs.erofs \
            --tar=f --all-root -T0 \
            -U bdfb6fc9-0000-4000-8000-000000000001 -L aos-root \
            --workers=0 -z zstd,level=1 -C262144 \
            -Eztailpacking,dedupe \
            deduplicated.erofs baseline-labeled.tar
          ${pkgs.erofs-utils}/bin/fsck.erofs deduplicated.erofs

          # Extraction cannot preserve security labels without builder
          # privilege. Compare content here, then read all labels and inode
          # metadata natively from both images below.
          ${pkgs.erofs-utils}/bin/fsck.erofs \
            --extract=deduplicated --preserve-perms deduplicated.erofs
          ${pkgs.diffutils}/bin/diff --recursive --no-dereference \
            baseline deduplicated
          ${pkgs.python3}/bin/python3 -B ${./verify-erofs-repack.py} \
            --dump-erofs ${pkgs.erofs-utils}/bin/dump.erofs \
            --policy-support ${policySupport} \
            --expected ${baselineRootfs}/rootfs-selinux-contexts.json \
            --baseline-image ${baselineRootfs}/root.img \
            --candidate-image deduplicated.erofs \
            --baseline-tree baseline --candidate-tree deduplicated \
            > measurement.json

          mkdir -p "$out"
          cp deduplicated.erofs "$out/root.img"
          cp measurement.json "$out/measurement.json"
          cat "$out/measurement.json"
        '';
      }
    ];
  }

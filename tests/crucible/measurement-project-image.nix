# Exercises the same installed-rootfs formatter without mounting a filesystem.
{pkgs}: let
  format = imageBytes:
    import ../../pkgs/tools/crucible/_measurement-project-image.nix {
      inherit pkgs imageBytes;
      projectBytes = 8589934592 + 1048576;
      projectInodes = 1048576 + 128;
    };
  positive = pkgs.writeTextFile {
    name = "crucible-project-image-positive.sh";
    text = format 12884901888;
  };
  insufficient = pkgs.writeTextFile {
    name = "crucible-project-image-insufficient.sh";
    text = format 6442450944;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-measurement-project-image-component";
    version = "0";
    src = null;
    buildDeps = [pkgs.bash pkgs.coreutils pkgs.e2fsprogs pkgs.fakeroot pkgs.findutils pkgs.gawk];
    phases = [
      {
        name = "check-real-disposable-image-geometry";
        script = ''
          mkdir -p "$out" positive/rootfs insufficient/rootfs
          printf 'immutable image input\n' > positive/rootfs/input
          printf 'immutable image input\n' > insufficient/rootfs/input
          (
            cd positive
            export out="$TMPDIR/positive.img" metadata="$TMPDIR/positive-metadata"
            ${pkgs.bash}/bin/bash -eu ${positive}
          ) > "$out/positive.log" 2>&1
          cp -R "$TMPDIR/positive-metadata" "$out/positive-metadata"
          if (
            cd insufficient
            export out="$TMPDIR/insufficient.img" metadata="$TMPDIR/insufficient-metadata"
            ${pkgs.bash}/bin/bash -eu ${insufficient}
          ) > "$out/insufficient.log" 2>&1; then
            printf 'Insufficient image unexpectedly passed the real capacity check\n' >&2
            exit 1
          fi
          ${pkgs.gawk}/bin/awk '
            /Disposable filesystem cannot cover the authored project partition/ { found = 1 }
            END { if (!found) exit 1 }
          ' "$out/insufficient.log"
          cp -R "$TMPDIR/insufficient-metadata" "$out/insufficient-metadata"
          rm "$TMPDIR/positive.img" "$TMPDIR/insufficient.img"
          printf 'offline_ext4_geometry=PASS\ninsufficient_capacity_refusal=PASS\nmounted_kernel_quota=NOT_RUN\n' > "$out/result"
        '';
      }
    ];
    passthru = {
      privateFixture = true;
      runtimeAdmission = false;
    };
  }

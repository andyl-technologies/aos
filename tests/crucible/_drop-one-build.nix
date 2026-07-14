# Expensive, classification-independent half of drop-one attribution for one
# patch: attempt to remove patch N from the series via a 3-way `git rebase
# --onto`, and — if it drops clean — build qemu-system from the full-minus-N
# tree. The raw outcome (conflict / build-failed / built, plus the retained
# variant binary and logs) is an OUTPUT; nothing is hardcoded. The cheap
# classifier (`_drop-one.nix`) consumes this and assigns the attribution method,
# so tuning the classification never rebuilds QEMU.
#
# outcome (in $out/outcome): one of
#   conflict      -- N cannot be removed without breaking a later patch's 3-way
#                    application ($out/conflict.env names the conflicting commit
#                    and files).
#   build-failed  -- N drops clean but full-minus-N fails to build ($out/build.log,
#                    $out/failing-symbols).
#   built         -- N drops clean and full-minus-N builds
#                    ($out/variant-qemu-system-x86_64).
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  index,
  attrPath ? "drop-one-build",
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = series.patchFiles;
  patchCount = builtins.length patchFiles;
  droppedPatch = builtins.elemAt patchFiles (index - 1);
  configureFlags = lib.escapeShellArgs qemuPackage.passthru.qemuConfigureFlags;
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-build-${toString index}";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.binutils
      pkgs.coreutils
      pkgs.gawk
      pkgs.git
      pkgs.glib
      pkgs.gnumake
      pkgs.grep
      pkgs.libslirp
      pkgs.meson
      pkgs.ninja
      pkgs.patch
      pkgs.pixman
      pkgs.pkg-config
      pkgs.python3
      pkgs.sed
      pkgs.setuptools
      pkgs.distlib
      pkgs.tar
      pkgs.xz
      pkgs.zlib
    ];
    runtimeDeps = [
      pkgs.glib
      pkgs.libslirp
      pkgs.pixman
      pkgs.zlib
    ];

    DROPPED_PATCH = droppedPatch;
    DROP_INDEX = toString index;
    PATCH_COUNT = toString patchCount;

    phases = [
      {
        name = "drop-one-build";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          printf '%s\n' "$DROPPED_PATCH" > "$out/dropped-patch"
          printf '%s\n' "$DROP_INDEX" > "$out/drop-index"

          fail() { echo "FAIL: $*" >&2; exit 1; }

          # Deterministic git commit chain, oldest->newest.
          src="$TMPDIR/qemu-src"
          mkdir -p "$src"
          tar -xf ${qemuPackage.src} -C "$src"
          cd "$src/qemu-${qemuPackage.version}"
          git init -q
          git config user.name "${series.deterministicAuthorName}"
          git config user.email "${series.deterministicAuthorEmail}"
          git config commit.gpgsign false
          git config core.autocrlf false
          git config advice.detachedHead false
          git add -A
          GIT_AUTHOR_NAME="${series.deterministicAuthorName}" \
          GIT_AUTHOR_EMAIL="${series.deterministicAuthorEmail}" \
          GIT_AUTHOR_DATE="${series.deterministicBaseDate}" \
          GIT_COMMITTER_NAME="${series.deterministicAuthorName}" \
          GIT_COMMITTER_EMAIL="${series.deterministicAuthorEmail}" \
          GIT_COMMITTER_DATE="${series.deterministicBaseDate}" \
            git -c commit.gpgsign=false commit -q -m "qemu-${series.qemuVersion}-base"

          : > "$TMPDIR/commits"
          git rev-parse HEAD >> "$TMPDIR/commits"
          for patch_name in ${builtins.concatStringsSep " " patchFiles}; do
            patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch_name" > /dev/null
            git add -A
            GIT_AUTHOR_NAME="${series.deterministicAuthorName}" \
            GIT_AUTHOR_EMAIL="${series.deterministicAuthorEmail}" \
            GIT_AUTHOR_DATE="${series.deterministicPatchDate}" \
            GIT_COMMITTER_NAME="${series.deterministicAuthorName}" \
            GIT_COMMITTER_EMAIL="${series.deterministicAuthorEmail}" \
            GIT_COMMITTER_DATE="${series.deterministicPatchDate}" \
              git -c commit.gpgsign=false commit -q -m "''${patch_name%.patch}"
            git rev-parse HEAD >> "$TMPDIR/commits"
          done
          head_commit=$(git rev-parse HEAD)
          test "$head_commit" = "${series.patchBranchHeadCommit}"

          onto=$(sed -n "$((DROP_INDEX))p" "$TMPDIR/commits")
          drop=$(sed -n "$((DROP_INDEX + 1))p" "$TMPDIR/commits")

          git checkout -q -B dropone "$head_commit"
          if [ "$DROP_INDEX" -eq "$PATCH_COUNT" ]; then
            git reset -q --hard "$onto"
            rebase_ok=1
          elif GIT_SEQUENCE_EDITOR=true GIT_EDITOR=true \
               git -c rerere.enabled=false rebase --onto "$onto" "$drop" dropone \
               > "$out/rebase.log" 2>&1; then
            rebase_ok=1
          else
            rebase_ok=0
            conflict_commit=$(gawk '/could not apply/ {
              sub(/.*could not apply /, ""); print; exit
            }' "$out/rebase.log")
            conflict_files=$(git diff --name-only --diff-filter=U 2>/dev/null | tr '\n' ',' | sed 's/,$//')
            git rebase --abort > /dev/null 2>&1 || true
          fi

          if [ "$rebase_ok" -eq 0 ]; then
            echo conflict > "$out/outcome"
            {
              echo "conflicting_replayed_commit=$conflict_commit"
              echo "conflicting_files=$conflict_files"
            } > "$out/conflict.env"
            exit 0
          fi

          # Prepare + build full-minus-N (match the shipped build's effective
          # flags: no -Werror; see _drop-one.nix history for why the git tree
          # otherwise auto-promotes upstream GCC-14 warnings to errors).
          mkdir -p include/aos/crucible
          cp ${qemuPackage.passthru.shmemGeneratedHeader} \
            include/aos/crucible/crucible_shmem_abi.h
          # Prune .git: the reconstructed commit chain leaves a live object
          # store whose loose objects git repacks asynchronously, so traversing
          # it races ("find: './.git/objects/XX': No such file or directory")
          # and fails the phase under pipefail. The QEMU python scripts we
          # rewrite never live under .git.
          find . -path ./.git -prune -o -type f -name '*.py' -print | while IFS= read -r f; do
            sed -i "1s|#!/usr/bin/env python3|#!${pkgs.python3}/bin/python3|" "$f"
            sed -i "1s|#!/usr/bin/python3|#!${pkgs.python3}/bin/python3|" "$f"
          done
          export PYTHONPATH="${pkgs.meson}/lib/python3/site-packages:${pkgs.distlib}/lib/python3.14/site-packages:${pkgs.setuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          export PYTHONDONTWRITEBYTECODE=1
          "$CONFIG_SHELL" ./configure \
            --prefix="$TMPDIR/install" \
            ${configureFlags} \
            --disable-werror \
            > "$out/configure.log" 2>&1 || fail "full-minus-$DROP_INDEX configure failed"
          rm -f subprojects/.wraplock

          if ninja -C build -j "$NIX_BUILD_CORES" qemu-system-x86_64 \
            > "$out/build.log" 2>&1; then
            echo built > "$out/outcome"
            cp build/qemu-system-x86_64 "$out/variant-qemu-system-x86_64"
          else
            echo build-failed > "$out/outcome"
            : > "$out/failing-symbols"
            grep -oE "undefined reference to .[A-Za-z_][A-Za-z0-9_]*'" "$out/build.log" \
              | sed -E "s/.*to .([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            grep -oE "implicit declaration of function '[A-Za-z_][A-Za-z0-9_]*'" "$out/build.log" \
              | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            grep -oE "'[A-Za-z_][A-Za-z0-9_]*' undeclared" "$out/build.log" \
              | sed -E "s/'([A-Za-z_][A-Za-z0-9_]*)' undeclared/\1/" >> "$out/failing-symbols" || true
            grep -oE "unknown type name '[A-Za-z_][A-Za-z0-9_]*'" "$out/build.log" \
              | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            LC_ALL=C sort -u "$out/failing-symbols" -o "$out/failing-symbols"
          fi
        '';
      }
    ];
  }

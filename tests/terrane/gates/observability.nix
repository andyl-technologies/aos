{
  pkgs,
  lib,
  sourceGateWithInputs,
  ...
}: let
  testing = import ../../../lib/testing {inherit pkgs lib;};
  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } "blame-test-image" ''
      cd crates
      cargo test --frozen --offline -p terrane-sdk --features tokio,surface-sdk \
        --test entry_blame --no-run --message-format=json > "$TMPDIR/blame-sdk-build.jsonl"
      cargo test --frozen --offline -p terrane-cli --test local_cli \
        --no-run --message-format=json > "$TMPDIR/blame-cli-build.jsonl"
      cargo metadata --frozen --offline --no-deps --format-version=1 \
        > "$TMPDIR/blame-packages.json"
      rustc --print target-libdir > "$TMPDIR/blame-target-libdir.txt"
      python3 ../tests/terrane/blame_test_image.py install
    '';
  proof = testing.mkVMTest {
    name = "terrane-obs-blame-ext4";
    memory = 1024;
    timeout = 300;
    rootfsDeps = [image pkgs.terrane.src pkgs.python3 pkgs.coreutils pkgs.diffutils pkgs.util-linux];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      export src=${pkgs.terrane.src}
      python3 "$src/tests/terrane/blame_test_image.py" bind-cli ${image} "$src"
      fixture_root=$(mktemp -d /var/terrane-blame.XXXXXXXX)
      trap 'rm -rf -- "$fixture_root"' EXIT
      test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
      chown 840:840 "$fixture_root"
      chmod 0700 "$fixture_root"
      export TMPDIR="$fixture_root"
      setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
        --inh-caps=-all --ambient-caps=-all --no-new-privs \
        python3 "$src/tests/terrane/blame_vm.py" ${image} "$src"
    '';
  };
in {
  obs-blame = sourceGateWithInputs {} "obs-blame" ''
    test "$(cat ${proof}/result)" = PASS
    mkdir -p "$out/nix-support"
    printf '%s\n' ${proof} > "$out/nix-support/blame-proof"
    printf '%s\n' ${image} > "$out/nix-support/blame-image"
    printf 'PASS: signed graph blame, scoped SDK reads, no object bodies and CLI merge audit\n' \
      > "$out/result"
  '';
}

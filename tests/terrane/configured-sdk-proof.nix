# These separate receipts prove this narrow configured leaf, not host-cache
# routing, deployed unit confinement, or the complete SURF-32 owning gate.
{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  helper = ./configured_sdk_proof.py;
  image =
    sourceGateWithInputs {
      # Only the immutable image preserves actual Cargo artifact bytes. Both
      # consumers verify its complete manifest after ordinary image fixups.
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.python3] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } "configured-sdk-image" ''
      cd crates
      cargo test --frozen --offline -p terrane-linux \
        --features tokio,terrane/surface-sdk --lib --no-run --message-format=json \
        > "$TMPDIR/configured-sdk-unit.jsonl"
      cargo build --frozen --offline -p terrane-linux \
        --features tokio,terrane/surface-sdk --example configured_sdk_fixture \
        --message-format=json > "$TMPDIR/configured-sdk-example.jsonl"
      cargo metadata --frozen --offline --no-deps --format-version=1 \
        > "$TMPDIR/configured-sdk-packages.json"
      rustc --print target-libdir > "$TMPDIR/configured-sdk-target-libdir"
      python3 ${helper} install ${./native_sdk_test_image.py}
    '';
  unit = sourceGateWithInputs {} "configured-sdk-unit" ''
    cd crates
    # Verification consumes the final image, including every retained launcher,
    # runtime library and identity byte. No result is inherited from discovery.
    python3 ${helper} unit ${image} "$src"
    printf '%s\n' 'PASS: all 11 actual configured SDK unit cases' > "$out/result"
  '';
  # This separate derivation consumes the completed image, so verification is
  # after its fixups and before the VM rootfs or guest can use its launchers.
  verifiedImage = pkgs.mkDerivation {
    pname = "terrane-configured-sdk-verified-image";
    version = "0.1.0";
    src = null;
    buildDeps = [pkgs.python3];
    phases = [
      {
        name = "verify";
        script = ''
          python3 ${helper} verify ${image} ${pkgs.terrane.src}
          mkdir -p "$out"
          printf '%s\n' '${image}' > "$out/verified-image"
        '';
      }
    ];
  };
  native = testing.mkVMTest {
    name = "terrane-configured-sdk-ext4";
    memory = 1024;
    rootfsDeps = [image verifiedImage pkgs.python3 pkgs.coreutils pkgs.util-linux];
    testScript = ''
      set -eu
      mount -o remount,rw /
      # /var is the writable guest ext4 rootfs, not /tmp or /run tmpfs.
      container=/var/lib/terrane-configured-sdk-proof
      [ ! -e "$container" ]
      mkdir -m 0700 "$container"
      trap 'rm -rf -- "$container"' EXIT
      [ "$(findmnt -n -o FSTYPE --target "$container")" = ext4 ]
      chown 840:840 "$container"
      python3 ${helper} verify ${image} ${pkgs.terrane.src}
      actor() {
        ${pkgs.util-linux}/bin/setpriv --reuid=840 --regid=840 --clear-groups \
          --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
          ${image}/bin/configured-sdk-example "$@"
      }
      # Each invocation is a new process. Setup creates its exclusive repository;
      # guest root creates/chowns only the enclosing fixture container.
      export TMPDIR="$container"
      actor setup "$container/success" 840
      actor run "$container/success" 840
      actor setup "$container/deny" 840
      [ -s "$container/deny/first.cap" ]
      [ -d "$container/deny/authority" ]
      [ -s "$container/deny/authority/issuer.seed" ]
      [ -s "$container/deny/authority/terminal.seed" ]
      [ -s "$container/deny/authority/token.cbor" ]
      [ -s "$container/deny/second.cap" ]
      rm -- "$container/deny/second.cap"
      actor deny-late "$container/deny" 840
      [ ! -e "$container/deny/snapshot-first" ]
      [ ! -e "$container/deny/snapshot-second" ]
      python3 ${helper} verify ${image} ${pkgs.terrane.src}
    '';
  };
in {inherit image unit native;}

##! aos-hub-worker-fixture — a signed PUBLIC registry surface fixture for
##! the RFC-0004 worker integration test, generated hermetically from source.
##!
##! Builds and runs the `gen_surface` example in `crates/aos-hub-worker`
##! (which reuses the wasm-clean `aos-registry-surface` signing primitives) to
##! emit a complete, correctly **signed** registry surface — the exact R2 key
##! layout the Worker's facade and Cron indexer consume:
##!
##! ```text
##! $out/surface/HEAD                       ref: refs/heads/stable
##! $out/surface/info/refs                  branch + release-tag advertisement
##! $out/surface/objects/<aa>/<rest>        loose commit + tree + blob + tag objects
##! $out/surface/channels/stable/00..ff     256 signed partitions (all → 1.0.0)
##! $out/surface/nix-cache-info             the Nix binary-cache header
##! $out/surface/h7j3k8l2m9n4.narinfo       one narinfo
##! $out/surface/nar/h7j3k8l2m9n4.nar.zst   one (placeholder) NAR
##! $out/trust_key                          the pinned trust-anchor line (for D1)
##! $out/head_commit                        the HEAD commit oid (for assertions)
##! ```
##!
##! The surface is signed by a deterministic maintainer Ed25519 key; the pinned
##! trust line in `$out/trust_key` is what the test stores in the registry's
##! `trust_keys`, so the Cron indexer verifies it cleanly (assertion e). The
##! facade/narinfo/nar bytes are plain R2 objects (no signature) used by the
##! read-path assertions (a/b).
{
  mkDerivation,
  fetchCargoDeps,
  rust,
  protobuf,
}: let
  version = "0.1.0";

  src = builtins.path {
    path = ../../crates;
    name = "aos-crates-src";
    filter = path: _type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };
in
  mkDerivation {
    pname = "aos-hub-worker-fixture";
    inherit version src;

    buildDeps = [rust protobuf];

    # Same workspace vendor set as the dist package (the example adds no new
    # crate — ed25519-dalek is already in the lockfile via aos-registry-surface).
    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-k0mK+JO/PJNV2L/hzIpiT/ALzsRVQqir8dU3f99452Q=";
    };

    phases = [
      {
        name = "unpack";
        script = ''
          cp -r "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n\n' \
            "$cargoDeps" > .cargo/config.toml
        '';
      }
      {
        name = "generate";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          # aos-proto-types' build script needs protoc (the worker pulls it in
          # via aos-hub-core).
          export PROTOC="${protobuf}/bin/protoc"
          mkdir -p "$out/surface"
          # Build + run the host-target fixture generator. It writes the surface
          # tree under $out/surface and prints the trust line + HEAD oid.
          cargo run \
            -p aos-hub-worker \
            --example gen_surface \
            --release \
            --frozen \
            --offline \
            -j"$NIX_BUILD_CORES" \
            -- "$out/surface" > gen-out.txt

          # Split the two reported lines into files the test reads.
          while IFS=' ' read -r tag rest; do
            case "$tag" in
              TRUST_KEY)   printf '%s' "$rest" > "$out/trust_key" ;;
              HEAD_COMMIT) printf '%s' "$rest" > "$out/head_commit" ;;
            esac
          done < gen-out.txt

          test -s "$out/trust_key"
          test -s "$out/head_commit"
          test -f "$out/surface/nix-cache-info"
          test -f "$out/surface/channels/stable/ff"
        '';
      }
    ];

    meta = {
      description = "Signed public registry surface fixture for the RFC-0004 worker integration test";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }

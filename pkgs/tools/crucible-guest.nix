##! crucible-guest — static RFC-0010 guest white-box emitter
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  patchelf,
}: let
  version = "0.1.0";
  src = import ./crucible/_source.nix {inherit lib;};
in
  mkCargoPackage {
    pname = "crucible-guest";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
    };

    cargoFlags = "-p crucible-guest --bin crucible-guest";
    cargoTestFlags = "-p crucible-guest";
    doCheck = true;
    buildDeps = [patchelf];

    preBuild = ''
      target_triple="$(rustc -vV | sed -n 's/^host: //p')"
      rustflags_var="CARGO_TARGET_$(printf '%s' "$target_triple" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
      export "$rustflags_var=-C target-feature=+crt-static"
      cd crates
    '';

    postInstall = ''
      test -x "$out/bin/crucible-guest"
      if patchelf --print-interpreter "$out/bin/crucible-guest" > "$TMPDIR/crucible-guest.interpreter" 2>/dev/null; then
        printf 'crucible-guest unexpectedly has ELF interpreter: '
        cat "$TMPDIR/crucible-guest.interpreter"
        exit 1
      fi

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-guest-build-info" <<'INFO'
      package=crucible-guest
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      cargo_package=crucible-guest
      cargo_binary=crucible-guest
      rustflags=-C target-feature=+crt-static
      packaged_guest_system=${lib.system}
      instruction_abi_architectures=x86_64,aarch64
      abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS
      frame_source=crucible-protocol::doorbell_frame
      marker_source=crucible-protocol::doorbell_marker
      INFO
    '';

    meta = {
      description = "Static Crucible guest white-box marker emitter";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
      mainProgram = "crucible-guest";
    };
  }

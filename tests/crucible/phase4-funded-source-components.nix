# Source-built component inputs; this check does not qualify the controller package.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  worker = pkgs.crucible-source-birth-worker;
  component = {
    name,
    flags,
    outputs,
    defaultCli ? false,
  }:
    pkgs.mkDerivation {
      pname = name;
      version = "0";
      src = source;
      buildDeps = [
        pkgs.coreutils
        pkgs.jq
        pkgs.openssl
        pkgs.pkg-config
        pkgs.protobuf
        pkgs.rust
        pkgs.sed
        pkgs.sqlite
      ];
      runtimeDeps = [pkgs.openssl pkgs.sqlite worker];
      dontStrip = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "build";
          script = ''
            set -eu
            export CARGO_HOME="$TMPDIR/cargo"
            export OPENSSL_DIR=${pkgs.openssl}
            export OPENSSL_LIB_DIR=${pkgs.openssl}/lib
            export OPENSSL_INCLUDE_DIR=${pkgs.openssl}/include
            export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0
            export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
            export PROTOC=${pkgs.protobuf}/bin/protoc
            export CRUCIBLE_SOURCE_BIRTH_WORKER_MANIFEST=${worker}/share/crucible/source-birth-worker/installation.json
            export RUSTFLAGS="-C link-arg=-Wl,-rpath,${pkgs.openssl}/lib -C link-arg=-Wl,-rpath,${pkgs.sqlite}/lib"
            mkdir -p "$CARGO_HOME" .cargo "$out/bin" "$out/share/component"
            sed "s|@vendor@|${cargoDeps}|g" \
              "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
            cargo build --frozen --offline --release -j"$NIX_BUILD_CORES" \
              --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
              --message-format=json-render-diagnostics ${flags} > "$TMPDIR/compiler.jsonl"
            ${lib.concatMapStringsSep "\n" (output: ''
                cp "$TMPDIR/target/release/${output.path}" "$out/bin/${output.name}"
              '')
              outputs}
            jq -s '[.[] | select(.reason == "compiler-artifact") |
              {package_id, target: .target.name, features} |
              select(.target | test("^crucible_(engine|daemon|session|qemu_host)$"))]' \
              "$TMPDIR/compiler.jsonl" > "$out/share/component/selected-features.json"
            ${lib.optionalString defaultCli ''
              # Separate Cargo invocation/target directory prevents test-support
              # unification with the observation executable's dev dependencies.
              jq -e '([.[].target] | unique | sort) ==
                ["crucible_daemon", "crucible_engine", "crucible_qemu_host", "crucible_session"]
                and all(.[];
                ((.features | index("test-support")) == null) and
                ((.features | index("test-double")) == null))' \
                "$out/share/component/selected-features.json"
            ''}
            sha256sum crates/Cargo.lock crates/crucible/control/crucible-daemon/Cargo.toml \
              > "$out/share/component/source-inputs.sha256"
            printf '%s\n' component-only package-and-strict-acceptance-pending \
              > "$out/share/component/scope"
          '';
        }
      ];
    };
  support = component {
    name = "crucible-funded-source-support-components";
    flags = "-p crucible-daemon --features test-support --example crucible-complete-scene-fixture --example crucible-funded-source-templates-flight";
    outputs = [
      {
        path = "examples/crucible-complete-scene-fixture";
        name = "crucible-complete-scene-fixture";
      }
      {
        path = "examples/crucible-funded-source-templates-flight";
        name = "crucible-funded-source-templates-flight";
      }
    ];
  };
  cli = component {
    name = "crucible-funded-source-default-cli-component";
    flags = "-p crucible-cli --bin crucible";
    defaultCli = true;
    outputs = [
      {
        path = "crucible";
        name = "crucible";
      }
    ];
  };
  peers = component {
    name = "crucible-funded-source-ordinary-peer-components";
    flags = "-p crucible-node-transport --bin crucible-reference-packet-provider --bin crucible-reference-device";
    outputs = [
      {
        path = "crucible-reference-packet-provider";
        name = "crucible-reference-packet-provider";
      }
      {
        path = "crucible-reference-device";
        name = "crucible-reference-device";
      }
    ];
  };
  buildClosure = (lib.build.closureInfo {inherit pkgs lib;}) {
    rootPaths = [source cargoDeps pkgs.rust pkgs.coreutils pkgs.sed pkgs.pkg-config pkgs.protobuf pkgs.openssl pkgs.sqlite];
    pname = "crucible-funded-source-component-build-inputs";
  };
in {
  inherit source support cli peers buildClosure worker;
}

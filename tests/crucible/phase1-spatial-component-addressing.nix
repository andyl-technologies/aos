{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialComponentAddressing",
  taskIds ? ["T-SPAT-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-3 completion names test";
        needle = "`spatial_components_have_independent_content_addresses_and_cross_reuse`";
      }
      {
        label = "T-SPAT-3 completion names gate";
        needle = "`checks.crucible.phase1.spatialComponentAddressing`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world content address accessor";
        needle = "pub fn id(&self) -> ContentHash";
      }
      {
        label = "world content address domain";
        needle = "\"crucible.model.world.v1\"";
      }
      {
        label = "world canonical bytes";
        needle = "pub fn canonical_bytes(&self) -> Vec<u8>";
      }
      {
        label = "plan content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "plan content address domain";
        needle = "\"crucible.model.plan.v1\"";
      }
      {
        label = "plan entries accessor";
        needle = "pub fn entries(&self) -> &[PlanEntry]";
      }
      {
        label = "properties content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "properties content address domain";
        needle = "\"crucible.model.properties.v1\"";
      }
      {
        label = "properties assertions accessor";
        needle = "pub fn assertions(&self) -> &[AssertionDef]";
      }
      {
        label = "scenario tuple uses world ref";
        needle = "world_ref={}";
      }
      {
        label = "scenario tuple uses plan ref";
        needle = "plan_ref={}";
      }
      {
        label = "scenario tuple uses properties ref";
        needle = "properties_ref={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "focused component addressing test";
        needle = "fn spatial_components_have_independent_content_addresses_and_cross_reuse()";
      }
      {
        label = "test checks world BLAKE3 domain";
        needle = "\"crucible.model.world.v1\"";
      }
      {
        label = "test checks plan BLAKE3 domain";
        needle = "\"crucible.model.plan.v1\"";
      }
      {
        label = "test checks properties BLAKE3 domain";
        needle = "\"crucible.model.properties.v1\"";
      }
      {
        label = "test reuses plan across worlds";
        needle = "plan_reused";
      }
      {
        label = "test reuses properties across worlds";
        needle = "properties_reused";
      }
      {
        label = "test reuses one world across many defs";
        needle = "reused_world_form";
      }
      {
        label = "test checks component identity isolation";
        needle = "reused_plan_properties_form";
      }
      {
        label = "test checks changed plan changes scenario";
        needle = "changed_plan_form";
      }
      {
        label = "test checks changed properties changes scenario";
        needle = "changed_properties_form";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial component addressing check";
        needle = "spatialComponentAddressing = import ./phase1-spatial-component-addressing.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial component addressing check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-component-addressing";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-spatial-component-addressing";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-component-addressing-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              spatial_components_have_independent_content_addresses_and_cross_reuse \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            component=spatial-component-addressing
            addressed_components=World,Plan,Properties
            cross_reuse=true
            RESULT
          '';
        }
      ];
    }

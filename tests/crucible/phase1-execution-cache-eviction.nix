{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionCacheEviction",
  taskIds ? ["T-EXEC-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  session = import ./_crucible-session-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "runtime cache field";
        needle = "runtime: Option<RuntimeState>";
      }
      {
        label = "runtime instantiation marker";
        needle = "runtime_instantiated: bool";
      }
      {
        label = "runtime cache eviction API";
        needle = "pub fn evict_runtime_cache(&mut self) -> EngineSnapshot";
      }
      {
        label = "runtime cache reinstantiate API";
        needle = "pub fn reinstantiate_runtime_cache(&mut self) -> Result<EngineSnapshot, SessionError>";
      }
      {
        label = "runtime cache refresh API";
        needle = "pub fn refresh_runtime_cache(&mut self) -> Result<EngineSnapshot, SessionError>";
      }
      {
        label = "cache eviction drops runtime only";
        needle = "self.runtime = None;";
      }
      {
        label = "cache rebuild uses source configuration";
        needle = "let runtime = self.graph.resume(&self.configuration)?.runtime;";
      }
      {
        label = "loaded-state rebuild guard";
        needle = "if !self.runtime_instantiated";
      }
      {
        label = "pause-boundary no-observable-change test";
        needle = "engine_runtime_cache_reinstantiates_without_observable_change_at_pause_boundary";
      }
      {
        label = "running-boundary no-observable-change test";
        needle = "engine_runtime_cache_reinstantiates_after_running_quantum_boundary";
      }
      {
        label = "loaded-state rejection test";
        needle = "engine_runtime_cache_reinstantiate_rejects_loaded_state_without_mutation";
      }
      {
        label = "never-instantiated stopped rejection test";
        needle = "engine_runtime_cache_reinstantiate_rejects_never_instantiated_stopped_state";
      }
      {
        label = "refresh failure preserves cache test";
        needle = "engine_runtime_cache_refresh_preserves_cache_when_reinstantiate_fails";
      }
      {
        label = "snapshot equality assertion";
        needle = "assert_eq!(engine.snapshot(), before_snapshot);";
      }
      {
        label = "runtime equality assertion";
        needle = "assert_eq!(engine.runtime(), Some(&before_runtime));";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution cache-eviction check";
        needle = "executionCacheEviction = import ./phase1-execution-cache-eviction.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-16 completion note";
        needle = "Completed by `crates/crucible-session/src/lib.rs`: `Engine::evict_runtime_cache`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution cache-eviction check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-cache-eviction";
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
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-execution-cache-eviction";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-cache-eviction-target" \
              -p crucible-session \
              --lib \
              runtime_cache \
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
            gate=gate:replay-oracle
            cache=runtime-state
            source_of_truth=configuration
            observable_change=none
            RESULT
          '';
        }
      ];
    }

{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCas",
  taskIds ? ["T-PKG-17"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  workspaceManifest = builtins.fromTOML (builtins.readFile ../../crates/Cargo.toml);
  packageInventory = import ../../pkgs/tools/crucible/_packages.nix;
  casManifest = builtins.fromTOML (builtins.readFile ../../crates/crucible-cas/Cargo.toml);
  casSource =
    builtins.readFile ../../crates/crucible-cas/src/lib.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_codec.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_model.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/campaign_store.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/invalidation.rs
    + builtins.readFile ../../crates/crucible-cas/src/cas/tests.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  dependencies = casManifest.dependencies or {};
  dependencyNames = builtins.attrNames dependencies;
  forbiddenDependencyNames =
    builtins.filter
    (name: lib.hasPrefix "ratchet-" name || lib.hasPrefix "aos-nix-" name)
    dependencyNames;

  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-17 checklist complete";
        needle = "- [x] **T-PKG-17**";
      }
      {
        label = "T-PKG-17 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCas`";
      }
      {
        label = "crucible-cas evidence";
        needle = "`crucible-cas`";
      }
    ]
    ++ failuresFor "crates/Cargo.toml" (builtins.readFile ../../crates/Cargo.toml) [
      {
        label = "crucible-cas workspace member";
        needle = "\"crucible-cas\"";
      }
      {
        label = "crucible-cas workspace dependency";
        needle = "crucible-cas = { path = \"crucible-cas\" }";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/_packages.nix" (builtins.readFile ../../pkgs/tools/crucible/_packages.nix) [
      {
        label = "crucible-cas package inventory member";
        needle = "\"crucible-cas\"";
      }
    ]
    ++ failuresFor "crates/crucible-cas/Cargo.toml" (builtins.readFile ../../crates/crucible-cas/Cargo.toml) [
      {
        label = "crucible-cas package name";
        needle = "name = \"crucible-cas\"";
      }
      {
        label = "BLAKE3 dependency";
        needle = "blake3 = { workspace = true }";
      }
      {
        label = "thiserror dependency";
        needle = "thiserror = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "crate-level standalone docs";
        needle = "no dependency on RFC-0007 `ratchet` crates";
      }
      {
        label = "content hash type";
        needle = "pub struct ContentHash";
      }
      {
        label = "BLAKE3 key function";
        needle = "blake3::hash(bytes)";
      }
      {
        label = "store trait";
        needle = "pub trait DagStore";
      }
      {
        label = "store put interface";
        needle = "fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError>;";
      }
      {
        label = "store get interface";
        needle = "fn get(&self, key: &ContentHash) -> Result<Vec<u8>, CasError>;";
      }
      {
        label = "store has interface";
        needle = "fn has(&self, key: &ContentHash) -> Result<bool, CasError>;";
      }
      {
        label = "memory store";
        needle = "pub struct MemoryDagStore";
      }
      {
        label = "local store";
        needle = "pub struct LocalDagStore";
      }
      {
        label = "two-level layout";
        needle = "self.root.join(&hex[0..2]).join(hex)";
      }
      {
        label = "dependency snapshot";
        needle = "pub struct DependencySnapshot";
      }
      {
        label = "invalidation query";
        needle = "pub struct InvalidationQuery";
      }
      {
        label = "invalid iff dependency hash changed";
        needle = "if before != after";
      }
      {
        label = "content-addressed store unit test";
        needle = "memory_store_deduplicates_identical_bytes";
      }
      {
        label = "dependency invalidation unit test";
        needle = "invalidation_is_gated_by_dependency_hash_changes";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 crucible-cas check imported";
        needle = "crucibleCas = import ./phase7-crucible-cas.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible-cas/Cargo.toml" (builtins.readFile ../../crates/crucible-cas/Cargo.toml) [
      {
        label = "ratchet dependency";
        needle = "ratchet-";
      }
      {
        label = "aos-nix dependency";
        needle = "aos-nix-";
      }
    ]
    ++ forbiddenFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "ratchet import";
        needle = "use ratchet";
      }
      {
        label = "aos-nix import";
        needle = "use aos_nix";
      }
    ]
    ++ map (name: "crates/crucible-cas/Cargo.toml: forbidden RFC-0007 dependency ${name}")
    forbiddenDependencyNames;
in
  if failures != []
  then throw "crucible phase7 crucible-cas check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-cas";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            crate=crucible-cas
            store_interface=put,get,has
            invalidation=dependency-gated-content-hash
            standalone_from_rfc_0007=true
            RESULT
          '';
        }
      ];
    }

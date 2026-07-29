{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleCasRatchetSeam",
  taskIds ? ["T-PKG-18"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  casSource = builtins.readFile ../../crates/crucible-cas/src/lib.rs;
  casManifest = builtins.readFile ../../crates/crucible-cas/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-18 checklist complete";
        needle = "- [x] **T-PKG-18**";
      }
      {
        label = "T-PKG-18 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleCasRatchetSeam`";
      }
    ]
    ++ failuresFor "crates/crucible-cas/src/lib.rs" casSource [
      {
        label = "future home";
        needle = "RFC-0007 is the future home";
      }
      {
        label = "narrow interface put";
        needle = "[`DagStore::put`]";
      }
      {
        label = "narrow interface get";
        needle = "[`DagStore::get`]";
      }
      {
        label = "narrow interface has";
        needle = "[`DagStore::has`]";
      }
      {
        label = "narrow interface invalidation";
        needle = "[`InvalidationQuery::evaluate`]";
      }
      {
        label = "thin adapter merge plan";
        needle = "thin adapter behind that unchanged interface";
      }
      {
        label = "ABI and determinism stability";
        needle = "no Crucible ABI or determinism contract may change";
      }
      {
        label = "content-address gate bar";
        needle = "gate:content-address";
      }
      {
        label = "replay-oracle gate bar";
        needle = "gate:replay-oracle";
      }
      {
        label = "e2e gate bar";
        needle = "gate:e2e-determinism";
      }
      {
        label = "no current dependency";
        needle = "no RFC-0007 dependency";
      }
      {
        label = "seam constant";
        needle = "pub const FUTURE_RATCHET_INTEGRATION_SEAM";
      }
      {
        label = "merge bar constant";
        needle = "pub const FUTURE_RATCHET_MERGE_BAR";
      }
      {
        label = "stability rule constant";
        needle = "pub const FUTURE_RATCHET_STABILITY_RULE";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 ratchet seam check imported";
        needle = "crucibleCasRatchetSeam = import ./phase7-crucible-cas-ratchet-seam.nix";
      }
    ]
    ++ lib.optionals (!(hasInfix "\"crucible-cas\"" (builtins.readFile ./phase1-standalone-dependencies.nix))) [
      "tests/crucible/phase1-standalone-dependencies.nix: structured standalone dependency lint must include crucible-cas"
    ]
    ++ lib.optionals (!(hasInfix "forbiddenExactNames = [\"ratchet\" \"aos-nix\"];" (builtins.readFile ./phase1-standalone-dependencies.nix))) [
      "tests/crucible/phase1-standalone-dependencies.nix: structured standalone dependency lint must reject exact ratchet/aos-nix names"
    ]
    ++ forbiddenFor "crates/crucible-cas/Cargo.toml" casManifest [
      {
        label = "ratchet dependency prefix";
        needle = "ratchet-";
      }
      {
        label = "aos-nix dependency prefix";
        needle = "aos-nix-";
      }
      {
        label = "exact ratchet dependency";
        needle = "ratchet =";
      }
      {
        label = "exact aos-nix dependency";
        needle = "aos-nix =";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 crucible-cas ratchet seam check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-cas-ratchet-seam";
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
            seam=crucible-cas::dag-store
            interface=put,get,has,invalidation-query
            merge_plan=thin-adapter-behind-unchanged-interface
            merge_bar=gate:content-address,gate:replay-oracle,gate:e2e-determinism
            standalone_from_rfc_0007=true
            RESULT
          '';
        }
      ];
    }

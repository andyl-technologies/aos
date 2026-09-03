##! Pure checks for package-maintenance metadata and derivation isolation.
{
  pkgs,
  lib,
}: let
  canarySpec = {
    schema = "aos.package-update/v1";
    unitId = "maintenance-fixture-1";
    family = "maintenance-fixture";
    stream = "1";
    owner = "pkgs/test/maintenance-fixture.nix";
    classification = "automatic";
    package = {
      currentVersion = "1.2.3";
      versionProjection = {
        kind = "component-field";
        component = "main";
        field = "comparisonVersion";
      };
    };
    components.main = {
      current = {
        upstreamId = "v1.2.3";
        comparisonVersion = "1.2.3";
      };
      discovery = {
        primary = {
          provider = "github-tags";
          repository = "andyl-technologies/maintenance-fixture";
          tagPrefix = "v";
        };
        advisors.repology.project = "maintenance-fixture";
      };
      releasePolicy = {
        strategy = "latest-in-series";
        versionScheme = "semver";
        series.major = 1;
      };
      sources.source = {
        fetcher = "fetchurl";
        urlTemplates = [
          {
            scheme = "https";
            authority = "example.invalid";
            path = [
              {
                parts = [
                  {literal = "maintenance-fixture-";}
                  {
                    componentField = {
                      component = "main";
                      field = "comparisonVersion";
                    };
                  }
                  {literal = ".tar.xz";}
                ];
              }
            ];
          }
        ];
        hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        hashMode = "flat";
        allowedRedirectHosts = ["example.invalid"];
      };
    };
    policy = {
      lifecycle = "supported";
      riskFloor = "low";
    };
  };
  upstream = pkgs.mkUpstream canarySpec;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
      '';
    }
  ];
  baseline = pkgs.mkDerivation {
    pname = "maintenance-derivation-identity-fixture";
    version = upstream.version;
    src = null;
    inherit phases;
  };
  annotated = pkgs.mkDerivation {
    pname = "maintenance-derivation-identity-fixture";
    version = upstream.version;
    src = null;
    inherit phases;
    update = upstream.forPackage {member = "maintenance-fixture";};
  };
  invalidContract = builtins.tryEval (
    (pkgs.mkUpstream (canarySpec // {unknownField = true;})).version
  );
  inventoryJson = builtins.toJSON pkgs.maintenanceInventory;
  zlibUnit = builtins.head (
    builtins.filter (unit: unit.unitId == "zlib-1") pkgs.maintenanceInventory.units
  );
in
  assert !invalidContract.success;
  assert baseline.drvPath == annotated.drvPath;
  assert !(builtins.hasAttr "update" annotated);
  assert annotated.passthru.aos.maintenance.unitId == "maintenance-fixture-1";
  assert upstream.version == "1.2.3";
  assert builtins.head upstream.components.main.sources.source.urls == "https://example.invalid/maintenance-fixture-1.2.3.tar.xz";
  assert inventoryJson != "";
  assert builtins.all (
    name:
      builtins.any (unit: builtins.elem name unit.members) pkgs.maintenanceInventory.units
  )
  pkgs.packageNames;
  assert zlibUnit.members == ["zlib"];
  assert zlibUnit.platforms == [pkgs.stdenv.hostPlatform.system];
    lib.throwIfNot
    (builtins.head pkgs.zlib.src.urls == "https://zlib.net/zlib-${zlibUnit.package.currentVersion}.tar.xz")
    "zlib derivation source diverged from its maintenance metadata"
    (pkgs.mkDerivation {
      pname = "package-maintenance-contract-check";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    })

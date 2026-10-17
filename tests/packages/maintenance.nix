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
    artifacts.goModules = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
      materializer = {
        kind = "go-modules";
        sourceRoot = ".";
        moduleRoots = ["."];
        builder = "fetchGoModules/v1";
      };
    };
    policy = {
      lifecycle = "supported";
      riskFloor = "low";
    };
  };
  upstream = pkgs.mkUpstream canarySpec;
  fixtureArtifact =
    upstream.components.main.sources.source
    // {
      passthru.aos.fixedOutput =
        upstream.components.main.sources.source.passthru.aos.fixedOutput
        // {
          kind = "go-modules";
        };
    };
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
    update = upstream.forPackage {
      member = "maintenance-fixture";
      artifacts.goModules = fixtureArtifact;
    };
  };
  invalidContract = builtins.tryEval (
    (pkgs.mkUpstream (canarySpec // {unknownField = true;})).version
  );
  securityDeclaration = {
    identities = [
      {
        kind = "ecosystem";
        ecosystem = "crates.io";
        name = "maintenance-fixture";
      }
    ];
    advisorySources = [{provider = "osv";}];
    versionScheme = "semver";
    dependencyCoverage = {
      state = "unknown";
      basis = "Source declaration only";
    };
  };
  securedUpstream = pkgs.mkUpstream (canarySpec
    // {
      components =
        canarySpec.components
        // {
          main = canarySpec.components.main // {security = securityDeclaration;};
        };
    });
  secured = pkgs.mkDerivation {
    pname = "maintenance-derivation-identity-fixture";
    version = upstream.version;
    src = null;
    inherit phases;
    assessment = securedUpstream.assessment;
  };
  invalidSecurity = builtins.tryEval (builtins.deepSeq (
      (pkgs.mkUpstream (canarySpec
        // {
          components =
            canarySpec.components
            // {
              main =
                canarySpec.components.main
                // {
                  security = securityDeclaration // {script = "execute-untrusted-scanner";};
                };
            };
        })).assessment
    )
    true);
  assessmentJson = builtins.toJSON pkgs.assessmentInventory;
  inventoryJson = builtins.toJSON pkgs.maintenanceInventory;
  zlibUnit = builtins.head (
    builtins.filter (unit: unit.unitId == "zlib-1") pkgs.maintenanceInventory.units
  );
in
  assert !invalidContract.success;
  assert baseline.drvPath == annotated.drvPath;
  assert baseline.drvPath == secured.drvPath;
  assert !invalidSecurity.success;
  assert secured.passthru.aos.assessment.components.main.identities == securityDeclaration.identities;
  assert upstream.assessment.components.main.identities
  == [
    {
      kind = "unmapped";
      reason = "identity-unmapped";
      explanation = "No reviewed advisory identity is declared for this component.";
    }
  ];
  assert !(secured ? assessment);
  assert !(annotated.passthru.aos.maintenance.components.main ? security);
  assert pkgs.assessmentInventory.maintenanceInventory == pkgs.maintenanceInventory;
  assert builtins.length pkgs.assessmentInventory.securityDeclarations == builtins.length pkgs.maintenanceInventory.units;
  assert assessmentJson != "";
  assert !(builtins.hasAttr "update" annotated);
  assert annotated.passthru.aos.maintenance.unitId == "maintenance-fixture-1";
  assert annotated.passthru.aos.maintenance.artifacts.goModules.derivation == upstream.components.main.sources.source.drvPath;
  assert !((pkgs.bazel.passthru.aos or {}) ? maintenance);
  assert upstream.version == "1.2.3";
  assert upstream.artifacts.goModules.hash == "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
  assert upstream.components.main.sources.source.passthru.aos.fixedOutput.kind == "url";
  assert builtins.head upstream.components.main.sources.source.urls == "https://example.invalid/maintenance-fixture-1.2.3.tar.xz";
  assert inventoryJson != "";
  assert builtins.all (
    name:
      builtins.any (unit: builtins.elem name unit.members) pkgs.maintenanceInventory.units
  )
  pkgs.packageNames;
  assert zlibUnit.members == ["zlib"];
  assert zlibUnit.platforms == builtins.sort builtins.lessThan pkgs.platformSupport.platforms;
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

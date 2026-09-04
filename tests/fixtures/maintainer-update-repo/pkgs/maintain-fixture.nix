{
  mkFixturePackage,
  mkUpstream,
}: let
  upstream = mkUpstream {
    schema = "aos.package-update/v1";
    unitId = "maintain-fixture-1";
    family = "maintain-fixture";
    stream = "1";
    owner = "pkgs/maintain-fixture.nix";
    classification = "automatic";

    package = {
      currentVersion = "1.0.0";
      versionProjection = {
        kind = "component-field";
        component = "main";
        field = "comparisonVersion";
      };
    };

    components.main = {
      current = {
        upstreamId = "v1.0.0";
        comparisonVersion = "1.0.0";
      };
      discovery.primary = {
        provider = "github-tags";
        repository = "andyl-technologies/maintain-fixture";
        tagPrefix = "v";
      };
      releasePolicy = {
        strategy = "latest-in-series";
        versionScheme = "semver";
        seriesMajor = 1;
        allowPrerelease = false;
        minimumAgeDays = 0;
      };
      sources.source = {
        fetcher = "fetchurl";
        urlTemplates = [
          {
            scheme = "https";
            authority = "aos.andyl.org";
            path = [
              {
                kind = "literal";
                value = "_assets";
              }
              {
                kind = "literal";
                value = "style.css";
              }
            ];
          }
        ];
        hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        hashMode = "flat";
        allowedRedirectHosts = ["aos.andyl.org"];
      };
    };

    policy = {
      lifecycle = "supported";
      riskFloor = "low";
      repairScope = [];
    };
  };
in
  mkFixturePackage {
    version = upstream.version;
    src = upstream.components.main.sources.source;
    update = upstream.forPackage {member = "maintain-fixture";};
  }

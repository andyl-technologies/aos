##! Concise, closed constructor for conventional single-source GitHub units.
{mkUpstream}: {
  unitId,
  family,
  member ? family,
  stream,
  owner,
  classification ? "automatic",
  version,
  upstreamId,
  repository,
  tagPrefix ? "",
  repology ? null,
  major,
  versionScheme ? "semver",
  minimumAgeDays ? 3,
  source,
  riskFloor ? "normal",
  lifecycle ? "supported",
  successorUnit ? null,
}: let
  advisors =
    if repology == null
    then {}
    else {repology.project = repology;};
  policy =
    {
      inherit lifecycle riskFloor;
    }
    // (
      if successorUnit == null
      then {}
      else {inherit successorUnit;}
    );
  upstream = mkUpstream {
    schema = "aos.package-update/v1";
    inherit unitId family stream owner classification;
    package = {
      currentVersion = version;
      versionProjection = {
        kind = "component-field";
        component = "main";
        field = "comparisonVersion";
      };
    };
    components.main = {
      current = {
        inherit upstreamId;
        comparisonVersion = version;
      };
      discovery = {
        primary = {
          provider = "github-tags";
          inherit repository tagPrefix;
        };
        inherit advisors;
      };
      releasePolicy = {
        strategy = "latest-in-series";
        inherit versionScheme;
        series.major = major;
        allowPrerelease = false;
        inherit minimumAgeDays;
      };
      sources.source = {
        fetcher = "fetchurl";
        urlTemplates =
          source.urlTemplates
          or [
            {
              scheme = "https";
              inherit (source) authority path;
            }
          ];
        inherit (source) hash;
        hashMode = source.hashMode or "flat";
        allowedRedirectHosts =
          source.allowedRedirectHosts
          or (
            if (builtins.head (source.urlTemplates or [{inherit (source) authority;}])).authority == "github.com"
            then [
              "codeload.github.com"
              "github.com"
              "objects.githubusercontent.com"
              "release-assets.githubusercontent.com"
            ]
            else [source.authority]
          );
      };
    };
    inherit policy;
  };
in {
  inherit (upstream) version components;
  update = upstream.forPackage {inherit member;};
  updateFor = member: upstream.forPackage {inherit member;};
}

# Update contract

A package opts into automated updates by building its version and sources from
an `mkUpstream` declaration (`pkgs/build-support/_upstream.nix`). The
declaration colocates the package version, each component's upstream identity,
discovery provider, release policy, and source hashes with the package source.
`mkUpstream` validates the closed schema at evaluation time, rejecting unknown
or missing fields. It returns the package `version`, each component's fetched
sources, and `forPackage`, which produces the inventory record for one member.
The package passes that record to `mkDerivation` as `update`, which publishes it
as `passthru.aos.maintenance`:

```nix
mkDerivation {
  inherit version;
  src = upstream.components.main.sources.source;
  update = upstream.forPackage {member = "zlib";};
  # ...
}
```

`forPackage` also takes the member's artifact derivations and checks that they
match the declared artifact slots and their fixed-output contracts.

## Example

`pkgs/compression/zlib.nix` declares a conventional single-source unit:

```nix
upstream = mkUpstream {
  schema = "aos.package-update/v1";
  unitId = "zlib-1";
  family = "zlib";
  stream = "1";
  owner = "pkgs/compression/zlib.nix";
  classification = "automatic";

  package = {
    currentVersion = "1.3.2";
    versionProjection = {
      kind = "component-field";
      component = "main";
      field = "comparisonVersion";
    };
  };

  components.main = {
    current = {
      upstreamId = "v1.3.2";
      comparisonVersion = "1.3.2";
    };
    discovery = {
      primary = {
        provider = "github-releases";
        repository = "madler/zlib";
        tagPrefix = "v";
      };
      advisors.repology.project = "zlib";
    };
    releasePolicy = {
      strategy = "latest-in-series";
      versionScheme = "semver";
      series.major = 1;
      allowPrerelease = false;
      minimumAgeDays = 3;
    };
    sources.source = {
      fetcher = "fetchurl";
      urlTemplates = [
        {
          scheme = "https";
          authority = "zlib.net";
          path = [
            {
              parts = [
                {literal = "zlib-";}
                {componentField = {component = "main"; field = "comparisonVersion";};}
                {literal = ".tar.xz";}
              ];
            }
          ];
        }
      ];
      hash = "sha256-16BlR4Ok2lKdG7eTt62cMxgCCvd2Z7yuNfldDkKnkvM=";
      hashMode = "flat";
      allowedRedirectHosts = ["zlib.net"];
    };
  };

  policy = {
    lifecycle = "supported";
    riskFloor = "normal";
  };
};
version = upstream.version;
```

## Fields

| Field | Values |
|---|---|
| `schema` | `aos.package-update/v1` |
| `classification` | `automatic` or `assisted` |
| `package.versionProjection` | Which component field (`comparisonVersion` or `upstreamId`) becomes the package version |
| `discovery.primary.provider` | `github-releases`, `github-tags`, or `go-releases`; GitHub providers take a `repository` and optional `tagPrefix` |
| `discovery.advisors` | Optional advisory sources; currently `repology.project` |
| `releasePolicy.strategy` | `latest-in-series`, `channel`, or `vcs-lineage` |
| `releasePolicy.versionScheme` | `semver`, `numeric`, or `provider` |
| `releasePolicy.series` | Optional `major` and `minor` bounds |
| `sources.<slot>.fetcher` | `fetchurl` |
| `sources.<slot>.hashMode` | `flat` or `recursive` |
| `policy.lifecycle` | `supported`, `security-only`, `frozen`, or `retiring` |
| `policy.riskFloor` | `low`, `normal`, `high`, or `critical` |

URL templates are structured rather than strings: `https` only, a fixed
authority, and path segments assembled from literals and component fields.
Candidate-controlled text must stay within one path segment and use only
unreserved URL characters and `+`, so a hostile upstream tag cannot change the
origin or path structure.

Artifact slots declare derived fixed-output inputs. Each lists the source or
artifact it is built from and a materializer of kind `cargo-deps`,
`cargo-vendor`, `go-modules`, `npm-deps`, or `bazel-deps`, with its source
root, patches, and builder. Generated repository outputs, such as a rewritten
`Cargo.lock` or npm lock file, declare their format and transformation so they
can be compare-and-swap edited like other literals.

## Constructors

- `mkGithubUpstream` (`_github-upstream.nix`) builds the full declaration for
  the common single-source GitHub case from a unit identity, version, upstream
  tag, repository, and source path.
- `mkManualUpstream` (`_manual-upstream.nix`) declares a complex or human-led
  unit with a `reason`, risk floor, and optional repair scope, lifecycle,
  successor unit, and review date. The tool reports such units but does not
  update them automatically.

Every literal the tool may change has exactly one declaration site in this
structure. Package expressions read their version and sources from `upstream`
rather than repeating the values.

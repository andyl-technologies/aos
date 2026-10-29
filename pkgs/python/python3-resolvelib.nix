##! python3-resolvelib — Abstract dependency resolution algorithm for Python
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
  stdenv,
}: let
  version = "1.2.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };

    pname = "python3-resolvelib";
    # resolvelib 1.x keeps its provider and reporter interfaces stable;
    # consumers such as ansible-core cap below the next major release.
    inherit version;

    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/source/r/resolvelib/resolvelib-${version}.tar.gz"];
      hash = "sha256-fQiiAi9uFs5AXWC2jDkPBU78/QR31Lm9AZzJQcKPrRw=";
    };

    buildDeps = [buildPackages.python3 buildPackages.setuptools];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd resolvelib-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Build through the declared backend so the installed distribution
          # metadata matches upstream for importlib.metadata consumers.
          PYTHONPATH=${buildPackages.setuptools}/${sitePackages} \
            ${buildPackages.python3}/bin/python3 -c \
              'from setuptools.build_meta import build_wheel; build_wheel("dist")'
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}" "$out/share/licenses/python3-resolvelib"
          ${buildPackages.python3}/bin/python3 - <<'PY'
          import os
          from pathlib import Path
          from zipfile import ZipFile

          wheel, = Path("dist").glob("*.whl")
          with ZipFile(wheel) as archive:
              archive.extractall(Path(os.environ["out"]) / "${sitePackages}")
          PY
          cp LICENSE "$out/share/licenses/python3-resolvelib/"
          ${lib.optionalString (!stdenv.isCross) ''
            PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
              'import importlib.metadata, resolvelib; assert resolvelib.__version__ == importlib.metadata.version("resolvelib") == "${version}"'
          ''}
        '';
      }
    ];

    qualification.packageProbe = let
      # A two-package index: "app" needs any "lib" release in [1, 3).
      provider = ''
        import glob, sys

        (site,) = glob.glob("@out@/lib/python*/site-packages")
        sys.path.insert(0, site)
        import resolvelib

        INDEX = {
            ("app", 1): {"lib": range(1, 3)},
            ("lib", 1): {},
            ("lib", 2): {},
        }

        class Provider(resolvelib.AbstractProvider):
            def identify(self, requirement_or_candidate):
                return requirement_or_candidate[0]

            def get_preference(self, identifier, *args, **kwargs):
                return identifier

            def find_matches(self, identifier, requirements, incompatibilities):
                # Both mappings hold one-shot iterators.
                bad = {candidate[1] for candidate in incompatibilities[identifier]}
                specs = [requirement[1] for requirement in requirements[identifier]]
                found = [
                    (name, version) for (name, version) in INDEX
                    if name == identifier and version not in bad
                    and all(version in spec for spec in specs)
                ]
                return sorted(found, key=lambda candidate: -candidate[1])

            def is_satisfied_by(self, requirement, candidate):
                return candidate[1] in requirement[1]

            def get_dependencies(self, candidate):
                return [(name, spec) for name, spec in INDEX[candidate].items()]

        resolver = resolvelib.Resolver(Provider(), resolvelib.BaseReporter())
      '';
    in
      lib.qualification.commandProbe {
        primary = {
          input = "A two-package index where app requires lib releases 1 or 2.";
          operation = "Resolve app through a minimal provider.";
          expected = "resolvelib pins app 1 and the newest compatible lib release.";
          files = {
            "probe.py" = ''
              ${provider}
              result = resolver.resolve([("app", range(1, 2))])
              assert dict(result.mapping) == {"app": ("app", 1), "lib": ("lib", 2)}, result.mapping
              print("resolvelib resolution passed")
            '';
          };
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 0;
              stdout.exact = "resolvelib resolution passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        badInput = {
          input = "A requirement for a lib release the index does not contain.";
          operation = "Resolve the unsatisfiable requirement.";
          expected = "resolvelib raises ResolutionImpossible.";
          files = {
            "probe.py" = ''
              ${provider}
              try:
                  resolver.resolve([("lib", range(5, 6))])
              except resolvelib.ResolutionImpossible:
                  sys.stderr.write("resolvelib rejected invalid input\n")
                  raise SystemExit(7)
              raise SystemExit("resolvelib accepted an unsatisfiable requirement")
            '';
          };
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 7;
              observes_rejection = true;
              stdout.exact = "";
              stderr.exact = "resolvelib rejected invalid input\n";
            }
          ];
          artifacts = [];
        };
      };

    meta = {
      description = "Resolve abstract dependencies into concrete ones";
      homepage = "https://github.com/sarugaku/resolvelib";
      license = "ISC";
    };
  }

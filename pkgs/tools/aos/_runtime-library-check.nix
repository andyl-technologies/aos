##! Verifies that native package wrappers retain their evaluator source library.
{
  mkDerivation,
  coreutils,
  grep,
  package,
  moduleLibrary,
}:
mkDerivation {
  pname = "aos-runtime-module-library-check";
  version = "0";
  src = null;
  buildDeps = [coreutils grep];
  exportReferencesGraph = [
    "apm-closure"
    package.apm
    "runtime-closure"
    package.packageRuntime
  ];

  phases = [
    {
      name = "check";
      script = ''
        for wrapper in ${package.apm}/bin/apm ${package.packageRuntime}/bin/aos-package-runtime; do
          grep -Fqx 'export AOS_PACKAGE_MODULE_LIBRARY="${moduleLibrary}"' "$wrapper"
        done

        grep -Fqx '${moduleLibrary}' apm-closure
        grep -Fqx '${moduleLibrary}' runtime-closure
        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}

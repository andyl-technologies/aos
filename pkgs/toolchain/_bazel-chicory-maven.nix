##! Maven module artifacts assembled from the source-built Chicory class tree.
{
  mkDerivation,
  buildPackages,
  chicoryPackage,
}: let
  version = chicoryPackage.version;
  modules = ["log" "wasm" "runtime"];
  targets = map (module: "com/dylibso/chicory/${module}/${version}/${module}-${version}.jar") modules;
in
  mkDerivation {
    pname = "bazel-chicory-maven";
    inherit version;
    src = chicoryPackage;
    passthru.sourceTargets = targets;

    buildDeps = [buildPackages.openjdk-21 buildPackages.unzip];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir classes
          unzip -q ${chicoryPackage}/share/java/chicory-${version}.jar -d classes

          # The bootstrap JAR compiles these three source modules together.
          # Preserve Maven's module boundaries to avoid duplicate class entries.
          ${builtins.concatStringsSep "\n" (map (module: ''
              test -d classes/com/dylibso/chicory/${module}
              destination="$out/maven/com/dylibso/chicory/${module}/${version}"
              mkdir -p "$destination"
              jar --create --no-manifest --date=1980-01-01T00:00:02Z \
                --file "$destination/${module}-${version}.jar" \
                -C classes com/dylibso/chicory/${module}
            '')
            modules)}
        '';
      }
    ];
  }

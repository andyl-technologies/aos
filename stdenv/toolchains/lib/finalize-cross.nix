##! Builds target exports with runtime references distinct from cross build tools.
{
  privateTools,
  buildTools,
  directory,
  bootstrapPerl ? false,
  libcBuildOverrides ? {},
  libcBuildPerl ? null,
  perlNssLibraries ? "-lnss_files -lnss_dns",
  binutilsSource ? directory + "/binutils.nix",
  gccBuildOverrides ? {},
}: let
  withRuntimeShell = import ./with-runtime-shell.nix;
  finish = package:
    withRuntimeShell {
      inherit package buildTools;
      shell = "${exports.bash}/bin/bash";
    };
  call = path: overrides: let
    function = import path;
    arguments = builtins.intersectAttrs (builtins.functionArgs function) (buildTools // privateTools);
  in
    function (arguments // overrides);

  # Libc's utility build needs Perl before the public compiler can use libc.
  # Keep that interpreter private; the exported Perl uses only public tools.
  constructionPerl =
    if libcBuildPerl != null
    then libcBuildPerl
    else
      import ./bootstrap-perl.nix {
        inherit buildTools;
        nssLibraries = perlNssLibraries;
        inherit (privateTools) buildPlatform;
        targetTools =
          privateTools
          // {
            bash = exports.bash;
            glibc = privateTools.crossGlibc;
          };
      };

  # Cross compilers keep their construction sysroot. Installed native drivers
  # and tools name the exported target sysroot and interpreter explicitly.
  manifest = call (directory + "/manifest.nix") {
    crossGlibc = exports.glibc;
  };
  toolNames = [
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "gawk"
    "findutils"
    "diffutils"
    "tar"
    "gzip"
    "patch"
  ];
  tools = builtins.listToAttrs (map (name: {
      inherit name;
      value = finish (privateTools.mkAutotoolsTool (manifest.${name} // {runtimeShell = "${exports.bash}/bin/bash";}));
    })
    toolNames);
  exports =
    tools
    // {
      bash = withRuntimeShell {
        package = privateTools.bash;
        inherit buildTools;
        shell = "$out/bin/bash";
      };
      inherit (privateTools) linuxHeaders;
      glibc =
        if bootstrapPerl
        then
          import ./finalize-libc.nix {
            inherit buildTools constructionPerl;
            package = finish (call (directory + "/cross-glibc.nix") ({perl = constructionPerl;} // libcBuildOverrides));
            runtimePerl = exports.perl;
          }
        else finish privateTools.crossGlibc;
      binutils = finish (call binutilsSource {
        crossGlibc = exports.glibc;
      });
      gcc = finish (call (directory + "/gcc.nix") ({
          crossGlibc = exports.glibc;
          binutils = exports.binutils;
        }
        // gccBuildOverrides));
    }
    // (
      if bootstrapPerl
      then {
        perl = import ./bootstrap-perl.nix {
          inherit buildTools;
          nssLibraries = perlNssLibraries;
          inherit (privateTools) buildPlatform;
          targetTools = privateTools // exports;
        };
      }
      else {}
    );
in
  exports

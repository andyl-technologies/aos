##! Build-only Nix seed restoration and finalized-artifact measurement.
##!
##! This adapter supplies DATA, not a runtime generation, floor or admission.
{
  mkDerivation,
  nix,
  nlohmann-json,
  boost,
  libarchive,
  openssl,
  libsodium,
  brotli,
  curl,
  libseccomp,
  sqlite,
  pkg-config,
  coreutils,
  gcc-libs,
  stdenv,
  buildPackages,
}: let
  buildPkgConfig =
    if stdenv.isCross
    then buildPackages.pkg-config
    else pkg-config;
  buildCoreutils =
    if stdenv.isCross
    then buildPackages.coreutils
    else coreutils;
  nixCxxLibraryInputs = import ./_nix-cxx-library-inputs.nix {
    inherit nix nlohmann-json boost libarchive openssl libsodium brotli curl libseccomp sqlite gcc-libs;
  };
in
  assert nix.version == "2.24.12";
    mkDerivation {
      pname = "aos-nix-generation-seed-builder";
      version = "1";
      src = ./aos-nix-generation-seed-builder;
      buildDeps = [buildPkgConfig buildCoreutils];
      runtimeDeps = nixCxxLibraryInputs;
      propagatedDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "build";
          script = ''
            nix_flags=$(pkg-config --cflags --libs nix-store nix-main nix-util) || exit 1

            $CXX -std=c++20 -O2 -Wall -Wextra \
              -I${nix.dev}/include/nix \
              -include config-util.hh -include config-store.hh -include config-main.hh \
              seed.cc $nix_flags \
              -Wl,-rpath,${nix}/lib -o aos-nix-generation-seed-builder
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/libexec"
            cp aos-nix-generation-seed-builder "$out/libexec/"
            chmod 0555 "$out/libexec/aos-nix-generation-seed-builder"
          '';
        }
      ];

      passthru.evidenceSources = [
        ./aos-nix-generation-seed-builder.nix
        ./aos-nix-generation-seed-builder/seed.cc
        ./_nix-cxx-library-inputs.nix
      ];

      meta = {
        description = "Build-only selected Nix NAR/LocalStore seed DATA producer";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }

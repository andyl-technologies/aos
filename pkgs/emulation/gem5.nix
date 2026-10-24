##! gem5 — Full-system architecture simulation with matching source enrichment
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  python3-3_12,
  scons,
  pkg-config,
  protobuf,
  abseil-cpp,
  zlib,
  hdf5,
  capstone,
  gperftools,
  gcc-libs,
  patch,
  grep,
  findutils,
  sed,
  libpng,
  valgrind,
  m4,
  openssl,
} @ arguments: let
  native = import ./_gem5/native-base.nix (builtins.removeAttrs arguments ["mkDerivation"]);
  makeFoundation = import ./_gem5/foundation.nix {
    inherit mkDerivation python3-3_12;
  };
  # Runtime caches are not implementation source and must not affect wrapper
  # identity or escape into its corresponding-source output.
  hostControls = builtins.path {
    path = ./_gem5;
    name = "_gem5";
    filter = path: _type: let
      name = builtins.baseNameOf path;
    in
      name != "__pycache__" && builtins.match ".*[.]py[co]" name == null;
  };
  recipes =
    map (name: ./. + "/${name}")
    (builtins.filter (name: builtins.match "gem5.*\\.nix" name != null)
      (builtins.attrNames (builtins.readDir ./.)));
in
  makeFoundation (native
    // {
      inherit hostControls;
      hostRecipes = recipes;
      hostLicenseInventory = ./gem5-patches/LICENSES.md;
      phases = [
        (builtins.elemAt native.phases 0)
        (builtins.elemAt native.phases 1)
        {
          name = "check";
          script = ''
            c++ -std=c++17 -O3 -flto -fno-strict-aliasing \
              -Isrc -Ibuild/ALL ${./_gem5/time-buffer-check.cc} \
              -o time-buffer-check
            ./time-buffer-check
            c++ -std=c++17 -O3 -Isrc \
              ${./_gem5/modeled-state-writer-check.cc} -lcrypto \
              -o modeled-state-writer-check
            ./modeled-state-writer-check
            c++ -std=c++17 -O3 -Isrc \
              ${./_gem5/modeled-reference-writer-check.cc} -lcrypto \
              -o modeled-reference-writer-check
            ./modeled-reference-writer-check
            build/ALL/gem5.opt --build-info
            build/ALL/gem5.opt --outdir=package-check --dump-config=config.ini \
              configs/learning_gem5/part2/hello_goodbye.py
            test -s package-check/config.ini
            test -s package-check/stats.txt
          '';
        }
        (builtins.elemAt native.phases 2)
      ];
    })

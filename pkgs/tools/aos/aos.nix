##! aos — AOS build tool
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  bash,
  git,
  gnupg,
  nix,
  openssh,
  perl,
  openssl,
  pkg-config,
  protobuf,
  tar,
  which,
  zstd,
}: let
  version = "0.1.0";
  # Every external tool the aos/apm/apr binaries shell out to by bare name
  # (resolved via $PATH). The wrappers below set PATH to exactly this, so the
  # binaries are hermetic — their behavior never depends on the caller's
  # environment. The caller's original PATH is stashed in AOS_HOST_PATH first:
  # user-supplied commands (e.g. `apr keys register --key-command`, which
  # typically invokes a host secret manager) run with that PATH restored, while
  # every internal shell-out keeps the hermetic one. Tools:
  #   git           registry, pack, and object-store operations
  #   gnupg         gpg: git shells out to it to create and verify OpenPGP
  #                 signatures on commits and tags; with the hermetic PATH set
  #                 here it must be present for those git operations to work
  #   nix           nix / nix-store: cache and store operations
  #   openssh       ssh-keygen, for `git -c gpg.format=ssh tag -s` release signing
  #   zstd          pack-delta compression and store decompression
  #   tar           extracting tree subpaths from `git archive` output
  #   which         check_command_exists() preflight in the drain/sysroot path
  #   bash          wrapper interpreter; avoids relying on /bin/sh on the host
  # These are declared as runtimeDeps below (not just buildDeps) so the
  # scrubPhase keeps their store-path references in the wrappers and pulls them
  # into the runtime closure; without that, nuke-refs would rewrite these paths
  # to placeholders and the wrappers would point at nonexistent stores.
  runtimeTools = [bash git gnupg nix openssh zstd tar which];
  runtimeBinPath = lib.makeBinPath runtimeTools;
  src = builtins.path {
    path = ../../../crates;
    name = "aos-crates-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    cargoFlags = "-p aos --features aos-core/native-eval";

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-EJ/R+NfinB7azlZ3bGruKiAbboDN/ce4pekRk0S350Y=";
    };

    buildDeps = [perl pkg-config openssl protobuf];
    runtimeDeps = [openssl] ++ runtimeTools;

    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export PROTOC="${protobuf}/bin/protoc"
      export AOS_NIX_ORACLE="${nix}/bin/nix-instantiate"
    '';

    doCheck = true;
    cargoTestFlags = "--workspace --features aos-core/native-eval";

    # Each of aos/apm/apr is the same binary, dispatched by argv[0]. We install
    # a thin wrapper per name that sets the hermetic runtime PATH and execs the
    # real binary via an `.<name>-unwrapped` entry (a symlink for apm/apr) so
    # argv[0] still selects the right personality. The wrapper execs an absolute
    # store path baked in at build time — deriving it with `dirname` would
    # require coreutils on PATH, defeating the point of the minimal PATH above.
    postInstall = ''
          mv $out/bin/aos $out/bin/.aos-unwrapped
          rm -f $out/bin/apr
          ln -s .aos-unwrapped $out/bin/.apm-unwrapped
          ln -s .aos-unwrapped $out/bin/.apr-unwrapped

          for name in aos apm apr; do
            cat > $out/bin/$name << 'WRAPPER'
      #!${bash}/bin/bash
      export AOS_HOST_PATH="''${AOS_HOST_PATH-$PATH}"
      export PATH="@PATH@"
      exec "@SELF@" "$@"
      WRAPPER
            sed -i \
              -e "s|@PATH@|${runtimeBinPath}|" \
              -e "s|@SELF@|$out/bin/.$name-unwrapped|" \
              $out/bin/$name
            chmod +x $out/bin/$name
          done
    '';

    checks = {
      testing,
      self,
      pkgs,
    }:
      import ./_tests.nix {
        inherit testing self pkgs;
      };

    meta = {
      description = "aos — AOS build tool";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }

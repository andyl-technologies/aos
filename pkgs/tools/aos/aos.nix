##! aos — AOS build tool
{
  mkCargoPackage,
  fetchCargoDeps,
  git,
  nix,
  perl,
  openssl,
  pkg-config,
  protobuf,
}: let
  version = "0.1.0";
  # Crates workspace source + vendored deps, shared with the Rust CI checks
  # (lib/testing/rust.nix) so the cargoDeps hash lives in exactly one place.
  workspace = import ./_workspace.nix {inherit fetchCargoDeps;};
  inherit (workspace) src cargoDeps;
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    cargoFlags = "-p aos";

    inherit cargoDeps;

    buildDeps = [perl pkg-config openssl protobuf git];
    runtimeDeps = [openssl];

    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export PROTOC="${protobuf}/bin/protoc"
    '';

    doCheck = true;
    cargoTestFlags = "--workspace";

    postInstall = ''
          mv $out/bin/aos $out/bin/.aos-unwrapped
          # Remove the duplicate apr binary (same binary, detected via argv[0])
          rm -f $out/bin/apr
          cat > $out/bin/aos << 'WRAPPER'
      #!/bin/sh
      export PATH="${git}/bin:${nix}/bin''${PATH:+:$PATH}"
      exec "$(dirname "$0")/.aos-unwrapped" "$@"
      WRAPPER
          chmod +x $out/bin/aos
          # apm = aos package (detected via argv[0])
          ln -s .aos-unwrapped $out/bin/.apm-unwrapped
          cat > $out/bin/apm << 'WRAPPER'
      #!/bin/sh
      export PATH="${git}/bin:${nix}/bin''${PATH:+:$PATH}"
      exec "$(dirname "$0")/.apm-unwrapped" "$@"
      WRAPPER
          chmod +x $out/bin/apm
          # apr = apm registry (detected via argv[0])
          ln -s .aos-unwrapped $out/bin/.apr-unwrapped
          cat > $out/bin/apr << 'WRAPPER'
      #!/bin/sh
      export PATH="${git}/bin:${nix}/bin''${PATH:+:$PATH}"
      exec "$(dirname "$0")/.apr-unwrapped" "$@"
      WRAPPER
          chmod +x $out/bin/apr
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

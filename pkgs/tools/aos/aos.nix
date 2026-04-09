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
}:
let
  version = "0.1.0";
  src = builtins.path {
    path = ../../../crates;
    name = "aos-crates-src";
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      base != "target" && base != ".git";
  };
in
mkCargoPackage {
  pname = "aos";
  inherit version src;

  cargoFlags = "-p aos";

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-hONL9ueIdOQdr4RlpRLuZ/mpCQ6RGiH7gL+1FOuHbz4=";
  };

  buildDeps = [ perl pkg-config openssl protobuf ];
  runtimeDeps = [ openssl ];

  preBuild = ''
    export OPENSSL_DIR="${openssl}"
    export OPENSSL_LIB_DIR="${openssl}/lib"
    export OPENSSL_INCLUDE_DIR="${openssl}/include"
    export OPENSSL_NO_VENDOR=1
    export OPENSSL_STATIC=0
    export PROTOC="${protobuf}/bin/protoc"
  '';

  doCheck = false;

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

  checks =
    {
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

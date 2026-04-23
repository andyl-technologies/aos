##! protobuf — Protocol Buffers compiler (pre-built binary)
##!
##! Uses a pre-built protoc binary, patchelf'd for AOS.
##! protoc is only needed as a build tool for Rust/Go crates that
##! generate code from .proto files.
{
  mkDerivation,
  fetchurl,
  patchelf,
  python3,
  bootstrapTools,
}: let
  version = "29.5";
in
  mkDerivation {
    pname = "protobuf";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/protocolbuffers/protobuf/releases/download/v${version}/protoc-${version}-linux-x86_64.zip"
      ];
      hash = "sha256-o/CUNjzSBcb3rw0bkwXLTIUXBD8mXNsYjwmMrpPoshc=";
    };

    buildDeps = [
      patchelf
      python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out

          # Extract zip using python3 (no unzip in AOS yet)
          python3 -c "
          import zipfile, sys
          with zipfile.ZipFile(sys.argv[1]) as z:
              z.extractall(sys.argv[2])
          " $src $out

          chmod +x $out/bin/protoc

          # Patchelf if dynamically linked; skip if static
          if readelf -l $out/bin/protoc 2>/dev/null | grep -q "INTERP"; then
            INTERP=$(cat ${bootstrapTools}/nix-support/dynamic-linker)
            RPATH="${bootstrapTools}/lib"
            patchelf --set-interpreter "$INTERP" --set-rpath "$RPATH" $out/bin/protoc
          fi

          # Verify it runs
          $out/bin/protoc --version
        '';
      }
    ];

    meta = {
      description = "Protocol Buffers compiler (pre-built binary)";
      homepage = "https://protobuf.dev";
      license = "BSD-3-Clause";
    };
  }

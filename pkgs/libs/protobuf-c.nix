##! protobuf-c — Protocol Buffers implementation for C
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  protobuf,
  abseil-cpp,
  zlib,
}: let
  version = "1.5.2";
in
  mkDerivation {
    pname = "protobuf-c";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/protobuf-c/protobuf-c/releases/download/v${version}/protobuf-c-${version}.tar.gz"
      ];
      hash = "sha256-4shicYc6eckrWP736/jeGqDfRzg0eovV1OZagKFtDSQ=";
    };

    buildDeps = [gnumake pkg-config protobuf];
    # protoc-gen-c links Abseil directly through libprotoc. Keep the dependency
    # explicit so reference scrubbing preserves its runtime search path.
    runtimeDeps = [protobuf abseil-cpp zlib];
    propagatedDeps = [protobuf abseil-cpp zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd protobuf-c-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static \
            PROTOC="${protobuf}/bin/protoc"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-protobuf-c";
        library = self;
        libs = ["-lprotobuf-c"];
        testSource = ''
          #include <protobuf-c/protobuf-c.h>
          #include <stdio.h>

          int main(void) {
              printf("%s\n", PROTOBUF_C_VERSION);
              return PROTOBUF_C_VERSION_NUMBER >= 1000000 ? 0 : 1;
          }
        '';
      };

      tool = testing.mkToolCheck {
        pname = "tool-protoc-gen-c";
        tool = self;
        command = "protoc-gen-c </dev/null >/dev/null";
      };
    };

    meta = {
      description = "Protocol Buffers implementation for C";
      homepage = "https://github.com/protobuf-c/protobuf-c/";
      license = "BSD-2-Clause";
      mainProgram = "protoc-gen-c";
    };
  }

##! protobuf-c — Protocol Buffers implementation for C
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  protobuf,
  buildPackages,
  abseil-cpp,
  zlib,
}: let
  version = "1.5.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "protobuf-c";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "protoc-c validates the declaration and generates both outputs.";
        "files" = {
          "answer.proto" = "syntax = \"proto3\";\npackage qualification;\nmessage Answer { int32 value = 1; }\n";
        };
        "input" = "A proto3 schema declaring one message with an int32 field.";
        "operation" = "Compile the schema into C source and header output through protoc-c.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/protoc-c"
              "--c_out=."
              "answer.proto"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "protoc-c rejects the schema with its parse-error status.";
        "files" = {
          "invalid.proto" = "syntax = \"proto3\";\nmessage Invalid { int32 value = ; }\n";
        };
        "input" = "A protobuf field declaration with no numeric tag.";
        "operation" = "Compile the malformed schema through protoc-c.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/protoc-c"
              "--c_out=."
              "invalid.proto"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/protobuf-c/protobuf-c/releases/download/v${version}/protobuf-c-${version}.tar.gz"
      ];
      hash = "sha256-4shicYc6eckrWP736/jeGqDfRzg0eovV1OZagKFtDSQ=";
    };

    # protoc generates target sources on the build machine during cross builds.
    buildDeps = [gnumake pkg-config protobuf buildPackages.protobuf];
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
        name = "patch";
        script = ''
          patch -p1 < ${./protobuf-c-protobuf-35.patch}
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
            PROTOC="${buildPackages.protobuf}/bin/protoc"
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

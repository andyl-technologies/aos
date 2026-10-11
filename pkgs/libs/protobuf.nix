##! protobuf — Protocol Buffers compiler and C++ runtime
##!
##! Built from the complete upstream source release with the AOS C++
##! toolchain. The compiler is used by Rust and Go packages that generate code
##! from .proto files; the installed libraries and headers support native C++
##! consumers too.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  pkg-config,
  abseil-cpp,
  zlib,
}: let
  version = "36.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "protobuf";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "protoc validates the declaration and writes its descriptor output.";
        "files" = {
          "answer.proto" = "syntax = \"proto3\";\npackage qualification;\nmessage Answer { int32 value = 1; }\n";
        };
        "input" = "A proto3 schema declaring one message with an int32 field.";
        "operation" = "Compile the schema into a descriptor set with protoc.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/protoc"
              "--descriptor_set_out=answer.pb"
              "answer.proto"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "protoc rejects the schema with its parse-failure status.";
        "files" = {
          "invalid.proto" = "syntax = \"proto3\";\nmessage Invalid { int32 value = ; }\n";
        };
        "input" = "A protobuf field declaration with no numeric tag.";
        "operation" = "Compile the malformed schema with protoc.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/protoc"
              "--descriptor_set_out=invalid.pb"
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
        "https://github.com/protocolbuffers/protobuf/releases/download/v${version}/protobuf-${version}.tar.gz"
      ];
      hash = "sha256-3HT6WC9VnL0xYU3f77SGj0PJGdcYS95RS7R/kMYCXrg=";
    };

    buildDeps = [
      cmake
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      abseil-cpp
      zlib
    ];
    propagatedDeps = [
      abseil-cpp
      zlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd protobuf-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_CXX_STANDARD=17 \
            -DBUILD_SHARED_LIBS=ON \
            -Dprotobuf_ABSL_PROVIDER=package \
            -Dabsl_DIR=${abseil-cpp}/lib/cmake/absl \
            -Dprotobuf_BUILD_TESTS=OFF \
            -Dprotobuf_BUILD_EXAMPLES=OFF \
            -Dprotobuf_WITH_ZLIB=ON \
            -DZLIB_ROOT=${zlib}
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .

          config=$out/lib/cmake/protobuf/protobuf-config.cmake
          sed -i "1i set(ZLIB_ROOT \"${zlib}\")" "$config"
          sed -i "1i set(utf8_range_DIR \"$out/lib/cmake/utf8_range\")" "$config"
          sed -i "1i set(absl_DIR \"${abseil-cpp}/lib/cmake/absl\")" "$config"

          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            echo "skipping protoc execution while cross-compiling for $AOS_TARGET_PLATFORM"
          else
            $out/bin/protoc --version

            mkdir -p "$TMPDIR/protobuf-consumer"
            cd "$TMPDIR/protobuf-consumer"
            cat > smoke.proto <<'EOF'
          syntax = "proto3";
          package aos.protobuf.smoke;
          message Probe { string value = 1; }
          EOF
            $out/bin/protoc --cpp_out=. smoke.proto
            cat > main.cc <<'EOF'
          #include "smoke.pb.h"

          int main() {
            aos::protobuf::smoke::Probe probe;
            probe.set_value("source-built");
            return probe.value() == "source-built" ? 0 : 1;
          }
          EOF
            cat > CMakeLists.txt <<'EOF'
          cmake_minimum_required(VERSION 3.16)
          project(aos_protobuf_consumer LANGUAGES CXX)
          find_package(Protobuf CONFIG REQUIRED)
          add_executable(protobuf-consumer main.cc smoke.pb.cc)
          target_link_libraries(protobuf-consumer PRIVATE protobuf::libprotobuf)
          EOF
            cmake -S . -B build \
              -DCMAKE_BUILD_TYPE=Release \
              -DProtobuf_DIR=$out/lib/cmake/protobuf
            cmake --build build -j$NIX_BUILD_CORES
            LD_LIBRARY_PATH="$out/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
              build/protobuf-consumer
          fi
        '';
      }
    ];

    meta = {
      description = "Protocol Buffers compiler and C++ runtime";
      homepage = "https://protobuf.dev";
      license = "BSD-3-Clause";
    };
  }

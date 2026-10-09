##! FBThrift compiler and serialization libraries.
##!
##! This is the upstream codegen/serialization profile. It deliberately does
##! not provide RPC transports or benchmark executables; all compiler generators
##! and serialization libraries in that profile remain available.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  pkg-config,
  python3,
  folly,
  fmt,
  boost,
  gflags,
  glog,
  gcc-libs,
  openssl,
  zlib,
  zstd,
  xxhash,
}: let
  version = "2026.10.9";
  revision = "59610f475b20849393834479d9bc3b4a58ff57bc";
  libraries = [folly fmt boost gflags glog gcc-libs openssl zlib zstd xxhash]
    ++ (folly.propagatedDeps or []);
  prefixPath = lib.concatStringsSep ";" (map toString ([boost.dev] ++ libraries));
  runtimeLibraryDirectories = map (package: "${package}/lib") libraries;
  installRpath = lib.concatStringsSep ";" runtimeLibraryDirectories;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "fbthrift-serialization";
    version = "=${version}";
    cacheCCompilers = true;

    src = fetchurl {
      urls = ["https://github.com/facebook/fbthrift/archive/${revision}.tar.gz"];
      hash = "sha256-wtzuZipC8/w8mx+c9dEeCVlRTvXe7mYY8WmGe/yS8Vo=";
    };

    buildDeps = [cmake ninja pkg-config python3 boost.dev];
    runtimeDeps = libraries;
    propagatedDeps = libraries ++ [boost.dev];

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A structure containing one integer field.";
        operation = "Generate C++ serialization bindings with the installed compiler.";
        expected = "The compiler generates bindings without an error.";
        files."answer.thrift" = "namespace cpp2 qualification\nstruct Answer { 1: i32 value; }\n";
        artifacts = [];
        steps = [{
          argv = ["@out@/bin/thrift1" "--gen" "mstch_cpp2" "answer.thrift"];
          exit_code = 0;
          stdout.exact = "";
        } {
          argv = ["@python@" "-c" "from pathlib import Path; assert Path('gen-cpp2/answer_types.h').is_file()"];
          exit_code = 0;
          stdout.exact = "";
          stderr.exact = "";
        }];
      };
      badInput = {
        input = "A structure with an incomplete field declaration.";
        operation = "Compile the malformed declaration.";
        expected = "The compiler rejects the schema.";
        files."invalid.thrift" = "struct Invalid { 1: i32 }\n";
        artifacts = [];
        steps = [{
          argv = ["@out@/bin/thrift1" "--gen" "mstch_cpp2" "invalid.thrift"];
          exit_code = 1;
          observes_rejection = true;
          stdout.exact = "";
        }];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd fbthrift-${revision}
        '';
      }
      {
        name = "configure";
        script = ''
          patch -p1 < ${./fbthrift-generated-dependencies.patch}
          cmake -S . -B build -G Ninja $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_PREFIX_PATH="${prefixPath}" \
            -DCMAKE_INSTALL_RPATH="$out/lib;${installRpath}" \
            -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
            -DCMAKE_SHARED_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DCMAKE_EXE_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
            -DBUILD_SHARED_LIBS=ON \
            -DTHRIFT_RPC=OFF \
            -DTHRIFT_BENCHMARKS=OFF
        '';
      }
      {
        name = "build";
        script = ''cmake --build build --parallel "$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p "$out/share/licenses/fbthrift-serialization"
          cp LICENSE "$out/share/licenses/fbthrift-serialization/LICENSE"
          if [ -f NOTICE ]; then
            cp NOTICE "$out/share/licenses/fbthrift-serialization/NOTICE"
          fi
        '';
      }
      {
        name = "check";
        script = ''
          # Installed tools and libraries must resolve their own runtime closure.
          unset LD_LIBRARY_PATH
          mkdir -p serialization-check
          cat > serialization-check/answer.thrift <<'EOF'
          namespace cpp2 qualification
          struct Answer { 1: i32 value; }
          EOF

          (
            cd serialization-check
            "$out/bin/thrift1" --gen mstch_cpp2 -o . answer.thrift
          )
          test -s serialization-check/gen-cpp2/answer_types.h
          test -s serialization-check/gen-cpp2/answer_types.cpp
          cat > serialization-check/main.cpp <<'EOF'
          #include "gen-cpp2/answer_types.h"
          #include <thrift/lib/cpp2/protocol/Serializer.h>
          #include <string>

          int main() {
            qualification::Answer original;
            original.value() = 42;
            const auto encoded =
                apache::thrift::CompactSerializer::serialize<std::string>(original);
            qualification::Answer decoded;
            apache::thrift::CompactSerializer::deserialize(encoded, decoded);
            return decoded.value().value() == 42 ? 0 : 1;
          }
          EOF
          cat > serialization-check/CMakeLists.txt <<'EOF'
          cmake_minimum_required(VERSION 3.24)
          project(serialization_check LANGUAGES CXX)
          find_package(folly CONFIG REQUIRED)
          find_package(FBThrift CONFIG REQUIRED)
          file(GLOB generated_sources "gen-cpp2/answer_*.cpp")
          if(NOT generated_sources)
            message(FATAL_ERROR "The compiler produced no C++ source files")
          endif()
          add_executable(serialization_check main.cpp ''${generated_sources})
          target_compile_features(serialization_check PRIVATE cxx_std_20)
          target_include_directories(serialization_check PRIVATE . gen-cpp2)
          target_link_libraries(serialization_check PRIVATE
            FBThrift::thriftprotocol FBThrift::thriftmetadata FBThrift::thrifttype)
          EOF

          cmake -S serialization-check -B serialization-check/build -G Ninja \
            $cmakeFlags \
            -DCMAKE_PREFIX_PATH="$out;${prefixPath}" \
            -DCMAKE_EXE_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib"
          cmake --build serialization-check/build --parallel "$NIX_BUILD_CORES"
          serialization-check/build/serialization_check

          cat > serialization-check/invalid.thrift <<'EOF'
          struct Invalid { 1: i32 }
          EOF
          compiler_status=0
          "$out/bin/thrift1" --gen mstch_cpp2 serialization-check/invalid.thrift \
            > serialization-check/invalid.stdout \
            2> serialization-check/invalid.stderr || compiler_status=$?
          test "$compiler_status" -eq 1
          test -s serialization-check/invalid.stderr
        '';
      }
    ];

    meta = {
      description = "FBThrift compiler and C++ serialization profile";
      homepage = "https://github.com/facebook/fbthrift";
      license = "Apache-2.0";
    };
  }

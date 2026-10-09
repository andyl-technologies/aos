##! Structured logging and failure diagnostics for native applications.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  coreutils,
  gflags,
  libunwind,
}: let
  version = "0.6.0-20231004";
  revision = "3411d58669fe07e70335b252299432a00d1e7c6c";
  consumerSource = ''
    #include <cstdio>
    #include <string>
    #include <glog/logging.h>

    int main(int argc, char** argv) {
        google::InitGoogleLogging(argv[0]);
        if (argc > 1) {
            const bool accepted = google::SendEmail("invalid address", "test", "body");
            google::ShutdownGoogleLogging();
            if (accepted) return 2;
            std::fputs("glog rejected invalid input\n", stderr);
            return 7;
        }
        std::string message;
        LOG_TO_STRING(INFO, &message) << "answer=42";
        google::ShutdownGoogleLogging();
        if (message.find("answer=42") == std::string::npos) return 2;
        return std::puts("glog api passed") == EOF;
    }
  '';
  probe = reject: {
    input =
      if reject
      then "A malformed destination email address."
      else "A logging message with a fixed payload.";
    operation =
      if reject
      then "Confirm SendEmail rejects the malformed address before invoking a mailer."
      else "Initialize logging, capture a message, and shut down logging.";
    expected =
      if reject
      then "The library rejects the invalid input."
      else "The public API returns the expected value.";
    files."consumer.cc" = consumerSource;
    artifacts = [];
    steps = [
      {
        argv =
          ["@cxx@" "consumer.cc" "-std=c++20" "-g" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"]
          ++ ["-I${builtins.unsafeDiscardStringContext (toString gflags)}/include" "-lglog"]
          ++ ["-o" "consumer"];
        exit_code = 0;
        stdout.exact = "";
      }
      ({
          argv =
            [
              "@work@/${
                if reject
                then "bad-input"
                else "primary"
              }/consumer"
            ]
            ++ (
              if reject
              then ["reject"]
              else []
            );
          exit_code =
            if reject
            then 7
            else 0;
          observes_rejection = reject;
          stdout.exact =
            if reject
            then ""
            else "glog api passed\n";
        }
        // (
          if reject
          then {stderr.exact = "glog rejected invalid input\n";}
          else {}
        ))
    ];
  };
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "glog";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = probe false;
      badInput = probe true;
    };
    version = "=${version}";

    src = fetchurl {
      urls = ["https://github.com/google/glog/archive/${revision}.tar.gz"];
      hash = "sha256-l2PgNhMXuDN1Fn7op14830g5Ixsk9yA4lT3k+Cdmmww=";
    };

    buildDeps = [cmake gnumake coreutils];
    runtimeDeps = [gflags libunwind];
    propagatedDeps = [gflags];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd glog-${revision}

          # Folly's shared libraries require the pre-export-header glog ABI
          # to expose its logging symbols. This matches the upstream build.
          # The stacktrace test takes GNU label addresses around a loop; GCC
          # optimization may merge those labels and invalidate the test fixture.
          printf '\nset_source_files_properties(src/stacktrace_unittest.cc PROPERTIES COMPILE_OPTIONS -O0)\n' >> CMakeLists.txt
          sed -i 's|/usr/bin/true|${coreutils}/bin/true|g' src/logging_unittest.cc
          sed -i '/set (CMAKE_C_VISIBILITY_PRESET hidden)/d; /set (CMAKE_CXX_VISIBILITY_PRESET hidden)/d; /set (CMAKE_VISIBILITY_INLINES_HIDDEN ON)/d' CMakeLists.txt
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_PREFIX_PATH="${gflags};${libunwind}" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_TESTING=ON \
            -DWITH_GFLAGS=ON \
            -DWITH_PKGCONFIG=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir build --output-on-failure
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p $out/share/licenses/glog
          cp COPYING AUTHORS $out/share/licenses/glog/
        '';
      }
    ];

    meta = {
      description = "Native logging and failure diagnostics library";
      homepage = "https://github.com/google/glog";
      license = "BSD-3-Clause";
    };
  }

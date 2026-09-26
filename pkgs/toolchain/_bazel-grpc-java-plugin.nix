##! Source-built gRPC Java protoc plugin for Bazel's source bootstrap.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  protobuf,
  abseil-cpp,
  zlib,
}: let
  version = "1.48.1";

  source = fetchgit {
    url = "https://github.com/grpc/grpc-java.git";
    ref = "v${version}";
    rev = "6e2e18bb728793df32b2ba195a954ad380e546de";
    hash = "sha256-mMiazItb6iWjz0TpiT8IhvsArYixnpp2j5Ng/u1EAMw=";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    sparsePaths = [
      "compiler/src/java_plugin/cpp"
      "LICENSE"
    ];
  };
in
  mkDerivation {
    pname = "bazel-grpc-java-plugin";
    inherit version;
    src = source;

    buildDeps = [protobuf buildPackages.pkg-config buildPackages.sed];
    runtimeDeps = [protobuf abseil-cpp zlib];

    phases = [
      {
        name = "build";
        script = ''
          cp -R "$src/compiler/src/java_plugin/cpp" cpp
          chmod -R u+w cpp

          # Protobuf 36 exposes descriptor names as string_view. This older
          # generator expects owning strings for concatenation and templates.
          sed -i \
            -e 's/method->name()/std::string(method->name())/g' \
            -e 's/service->name()/std::string(service->name())/g' \
            cpp/java_generator.cpp

          c++ -std=c++17 -O2 -DGRPC_VERSION=${version} \
            cpp/java_generator.cpp cpp/java_plugin.cpp \
            -L${protobuf}/lib -lprotoc $(pkg-config --libs protobuf) \
            -o protoc-gen-grpc-java
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm755 protoc-gen-grpc-java "$out/bin/protoc-gen-grpc-java"
          install -Dm644 "$src/LICENSE" "$out/share/licenses/grpc-java/LICENSE"
        '';
      }
    ];
  }

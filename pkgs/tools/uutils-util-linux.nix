##! uutils util-linux — Rust Linux system utilities.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  util-linux,
  llvm,
  glibc,
  linux-headers,
  stdenv,
  buildPackages,
}: let
  version = "0.0.1";
  revision = "5fe0580eb51e5d795798afed2b0c9dd41f6a93ce";
  buildLlvm =
    if stdenv.isCross
    then buildPackages.llvm
    else llvm;
  src = fetchurl {
    urls = ["https://github.com/uutils/util-linux/archive/${revision}.tar.gz"];
    hash = "sha256-asu+7qIuZHeTMjfkgheg7NlvciEYQaettrRO8fZKshk=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-uUdlln+QN5Zo2UDZvOWIz6cH/JRPiB8Cy3cxC/BdZxk=";
  };
in
  mkCargoPackage {
    pname = "uutils-util-linux";
    inherit version src cargoDeps;

    cargoFlags = "--bin util-linux";
    buildDeps = [pkg-config buildLlvm];
    runtimeDeps = [util-linux];
    doCheck = false;

    LIBCLANG_PATH = "${buildLlvm}/lib";
    preBuild = ''
      gcc_include=$("$CC" -print-file-name=include)
      export BINDGEN_EXTRA_CLANG_ARGS="-isystem $gcc_include -isystem ${glibc.dev}/include -isystem ${linux-headers}/include"
    '';

    postInstall = ''
      cargo tree --offline --depth 1 --edges normal,build --format '{p}' --prefix none \
        | sed -n 's/^uu_\([^ ]*\) .*/\1/p' \
        | while read -r utility; do
            ln -s util-linux "$out/bin/$utility"
          done

      test -L "$out/bin/rev"
      test -L "$out/bin/uuidgen"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-util-linux";
        tool = self;
        command = "printf 'abc\\n' | ${self}/bin/rev";
        expectedOutput = "cba";
      };
    };

    meta = {
      description = "Rust Linux system utilities";
      homepage = "https://github.com/uutils/util-linux";
      license = "MIT";
      mainProgram = "util-linux";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }

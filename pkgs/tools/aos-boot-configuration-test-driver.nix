##! Builds the source-built native boot adoption acceptance harness.
{
  mkAosCargoPackage,
  aosWorkspaceVendor,
  buildPackages,
  openssl,
  sqlite,
  libssh2,
  zlib,
  callPackage,
  buildDriver ? "cargo",
}: let
  withBuildDriver = selected: callPackage ./aos-boot-configuration-test-driver.nix {buildDriver = selected;};
  packageArguments = {
    pname = "aos-boot-configuration-test-driver";
    version = "0";
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
      role = "build-input";
    };
    cargoDeps = aosWorkspaceVendor;
    cargoRoot = "crates";
    # The installed libtest embeds synthetic store identities as fixture data.
    # Scrubbing them changes validation inputs and collapses distinct identities.
    nukeRefsKeep = map (hash: "/nix/store/${hash}-libtest-fixture") [
      "00000000000000000000000000000000"
      "00000000000000000000000000000001"
      "11111111111111111111111111111111"
      "22222222222222222222222222222222"
      "33333333333333333333333333333333"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "cccccccccccccccccccccccccccccccc"
      "dddddddddddddddddddddddddddddddd"
      "ffffffffffffffffffffffffffffffff"
      "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
      "llllllllllllllllllllllllllllllll"
      "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"
      "oooooooooooooooooooooooooooooooo"
    ];
    cargoBuildCommands = ["test --release --frozen --offline --no-run -p aos-package-manager --lib"];
    doCheck = false;
    buildDeps = [buildPackages.pkg-config buildPackages.protobuf buildPackages.cmake buildPackages.perl];
    runtimeDeps = [openssl sqlite libssh2 zlib];
    cargoEnv = {
      AOS_LIBSSH2_PREFIX = "${libssh2}";
      OPENSSL_DIR = "${openssl}";
      OPENSSL_LIB_DIR = "${openssl}/lib";
      OPENSSL_INCLUDE_DIR = "${openssl}/include";
      OPENSSL_NO_VENDOR = "1";
      OPENSSL_STATIC = "0";
    };
    meta = {
      description = "Checks native boot metadata source adoption and recovery";
      license = "Apache-2.0";
    };
    passthru = {
      inherit withBuildDriver;
      buildDriver = "cargo";
    };
  };
  cargoPackage = mkAosCargoPackage packageArguments;
in
  assert builtins.elem buildDriver ["cargo" "bazel"];
    if buildDriver == "bazel"
    then
      callPackage ./_aos-boot-configuration-driver-bazel.nix {
        inherit packageArguments;
        cargoFallback = cargoPackage;
      }
    else cargoPackage

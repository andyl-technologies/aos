##! Matches the unchanged Cargo registry fixture environment.
{pkgs}: {
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths = ["api/proto/aos/hub/v1/hub.proto"];
  };
  nativeLibraries = [pkgs.openssl pkgs.libssh2 pkgs.zlib pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config pkgs.cmake pkgs.perl pkgs.protobuf pkgs.git-minimal pkgs.openssh pkgs.zstd pkgs.nix pkgs.which];
  cargoSetup = ''
    export AOS_LIBSSH2_PREFIX="${pkgs.libssh2}"
    export OPENSSL_DIR="${pkgs.openssl}"
    export OPENSSL_LIB_DIR="${pkgs.openssl}/lib"
    export OPENSSL_INCLUDE_DIR="${pkgs.openssl}/include"
    export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 ZSTD_SYS_USE_PKG_CONFIG=1
    export SSL_CERT_FILE="${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt"
    unset SSL_CERT_DIR
    export PROTOC="${pkgs.protobuf}/bin/protoc"
    export PROTOC_INCLUDE="${pkgs.protobuf}/include"
    export AOS_NIX_STORE="${pkgs.nix}/bin/nix-store"
    export AOS_NIX_INSTANTIATE="${pkgs.nix}/bin/nix-instantiate"
    export AOS_TEST_IDENTITY_PRELOAD="$TMPDIR/aos-test-identity.so"
    cc -shared -fPIC -O2 -Wall -Wextra -Werror \
      -o "$AOS_TEST_IDENTITY_PRELOAD" ${../../crates/hub/aos-hub-native/tests/nix_builder_identity.c}
    registry_nix_root="$TMPDIR/registry-ability-nix"
    mkdir -p "$registry_nix_root/state/db" "$registry_nix_root/state/gcroots" \
      "$registry_nix_root/state/profiles" "$registry_nix_root/log"
    NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$registry_nix_root/state" \
      NIX_LOG_DIR="$registry_nix_root/log" NIX_REMOTE=local \
      ${pkgs.nix}/bin/nix-store --init
    export AOS_TEST_ABILITY_NIX_STORE_DIR=/nix/store
    export AOS_TEST_ABILITY_NIX_STATE_DIR="$registry_nix_root/state"
    export AOS_TEST_ABILITY_NIX_LOG_DIR="$registry_nix_root/log"
    export AOS_TEST_ABILITY_NIX_REMOTE=local
  '';
}

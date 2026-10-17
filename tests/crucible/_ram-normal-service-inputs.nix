# Builds actual semantic records and disposable test-only mutual-TLS identities.
{
  pkgs,
  lib,
  nativeQemu,
  nativePlugin,
  guest,
  rootImage,
  nativeFlightKind ? null,
}: let
  source = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
  artifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  artifactContract = artifacts.passthru.cargoArtifactContract;
  tool = pkgs.mkCargoPackage {
    pname = "crucible-normal-ram-input-writer";
    version = "0";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoArtifacts = artifacts;
    cargoArtifactContract = artifactContract;
    cargoEnv = artifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = ["build --frozen --offline --release -j$NIX_BUILD_CORES -p crucible-daemon --example normal_ram_fixture"];
    installBins = false;
    doCheck = false;
    buildDeps = [pkgs.jq pkgs.pkg-config pkgs.openssl pkgs.protobuf pkgs.sqlite];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    postInstall = ''
      executable=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "normal_ram_fixture" and .executable != null) | .executable' \
        "$NIX_BUILD_TOP/cargo-build-messages.jsonl")
      test -f "$executable"
      mkdir -p "$out/bin"
      cp "$executable" "$out/bin/normal-ram-fixture"
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-normal-ram-service-inputs";
    version = "0";
    src = null;
    buildDeps = [tool pkgs.coreutils pkgs.openssl pkgs.jq];
    phases = [
      {
        name = "author-semantic-inputs-and-test-identities";
        script = ''
          set -eu
          umask 077
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
            selected_kernel="$kernel"
          done
          test -f "$selected_kernel"
          ${tool}/bin/normal-ram-fixture "$out" "$selected_kernel" \
            ${rootImage}/root.ext4 ${guest}/initrd.img \
            ${nativeQemu}/bin/qemu-system-x86_64 \
            ${nativePlugin}/lib/libcrucible_qemu_plugin.so ${lib.optionalString (nativeFlightKind != null) (lib.escapeShellArg nativeFlightKind)}
          ln -s "$selected_kernel" "$out/kernel"

          # These keys authorize only the authored disposable test campaign. They
          # are intentionally public test artifacts, never deployment credentials.
          printf CRUCCA01 > "$out/component-authority.bin"
          ${pkgs.openssl}/bin/openssl rand 64 >> "$out/component-authority.bin"
          test "$(wc -c < "$out/component-authority.bin")" -eq 72
          ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 36500 \
            -subj '/CN=AOS disposable RAM test CA' \
            -keyout "$out/ca.key" -out "$out/ca.pem"
          ${pkgs.openssl}/bin/openssl req -newkey rsa:2048 -nodes \
            -subj '/CN=127.0.0.1' -keyout "$out/server.key" -out "$out/server.csr"
          printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$out/server.ext"
          ${pkgs.openssl}/bin/openssl x509 -req -days 36500 -in "$out/server.csr" \
            -CA "$out/ca.pem" -CAkey "$out/ca.key" -set_serial 1 \
            -extfile "$out/server.ext" -out "$out/server.pem"
          ${pkgs.openssl}/bin/openssl req -newkey rsa:2048 -nodes \
            -subj '/CN=AOS normal RAM fixture operator' \
            -keyout "$out/client.key" -out "$out/client.csr"
          printf 'extendedKeyUsage=clientAuth\n' > "$out/client.ext"
          ${pkgs.openssl}/bin/openssl x509 -req -days 36500 -in "$out/client.csr" \
            -CA "$out/ca.pem" -CAkey "$out/ca.key" -set_serial 2 \
            -extfile "$out/client.ext" -out "$out/client.pem"
          ${pkgs.openssl}/bin/openssl x509 -in "$out/client.pem" -outform DER > "$out/client.der"
          ${pkgs.openssl}/bin/openssl dgst -sha256 -r "$out/client.der" \
            | ${pkgs.coreutils}/bin/cut -d ' ' -f 1 > "$out/client.fingerprint"
          chmod 600 "$out"/*.key "$out/component-authority.bin"
        '';
      }
    ];
    passthru = {inherit tool;};
  }

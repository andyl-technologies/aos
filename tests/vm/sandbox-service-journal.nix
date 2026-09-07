# Real-credential qualification of the protected service journal opener.
{
  lib,
  testing,
  pkgs,
}: let
  probe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-service-journal-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-service-journal-probe";
    doCheck = false;
    # The journal crate's shared protocol dependency generates its Rust types.
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
  };
in
  testing.mkVMTest {
    name = "sandbox-service-journal";
    rootfsDeps = [probe pkgs.coreutils];
    memory = 256;
    testScript = ''
      unset LD_LIBRARY_PATH
      mkdir -p /var/lib/journal-proof/private /var/lib/journal-proof/writable/private
      chmod 0755 /var /var/lib /var/lib/journal-proof
      chmod 0777 /var/lib/journal-proof/writable
      chmod 0700 /var/lib/journal-proof/private /var/lib/journal-proof/writable/private
      chown 1000:1000 /var/lib/journal-proof/private /var/lib/journal-proof/writable/private

      # Keep the existing root and select numeric credentials with no
      # supplementary groups; this is credential qualification, not a chroot
      # isolation claim. AOS coreutils supplies this credential-switching path.
      test "$(${pkgs.coreutils}/bin/chroot --userspec=+1000:+1000 --groups= / ${pkgs.coreutils}/bin/id -G)" = 1000
      ${pkgs.coreutils}/bin/chroot --userspec=+1000:+1000 --groups= / \
        ${probe}/bin/aos-sandbox-service-journal-probe write /var/lib/journal-proof/private
      ${pkgs.coreutils}/bin/chroot --userspec=+1001:+1001 --groups= / \
        ${probe}/bin/aos-sandbox-service-journal-probe deny /var/lib/journal-proof/private
      ${pkgs.coreutils}/bin/chroot --userspec=+1000:+1000 --groups= / \
        ${probe}/bin/aos-sandbox-service-journal-probe deny /var/lib/journal-proof/writable/private
    '';
  }

# Negative qualification of the protected policy owner boundaries.
{
  lib,
  testing,
  pkgs,
}: let
  cacheDacProbe = pkgs.mkDerivation {
    pname = "aos-sandbox-cache-dac-negative-probe";
    version = "1";
    src = null;
    runtimeDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            -I${pkgs.linux-headers}/include \
            ${../sandbox/cache-dac-negative-probe.c} \
            -o aos-sandbox-cache-dac-negative-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-sandbox-cache-dac-negative-probe $out/bin/
        '';
      }
    ];
    meta = {
      description = "VM-only SCM_RIGHTS Cache DAC denial probe";
      license = "Apache-2.0";
    };
  };

  policyCutProbe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-policy-cut-negative-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-policy-cut-negative-probe";
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
  };
in
  testing.mkVMTest {
    name = "sandbox-policy-negative";
    rootfsDeps = [cacheDacProbe policyCutProbe pkgs.coreutils];
    memory = 256;
    testScript = ''
      unset LD_LIBRARY_PATH

      mkdir -p /var/lib/aos/sandboxd
      mkdir -p /var/lib/aos/sandbox/source-domains
      mkdir -p /var/lib/aos/sandbox/cache-residency/objects
      chmod 0755 /var /var/lib /var/lib/aos /var/lib/aos/sandbox
      chmod 0700 /var/lib/aos/sandboxd /var/lib/aos/sandbox/source-domains
      chmod 0700 /var/lib/aos/sandbox/cache-residency
      chmod 0700 /var/lib/aos/sandbox/cache-residency/objects
      chown 811:811 /var/lib/aos/sandboxd /var/lib/aos/sandbox/source-domains
      chown 811:811 /var/lib/aos/sandbox/cache-residency
      chown 811:811 /var/lib/aos/sandbox/cache-residency/objects

      touch /var/lib/aos/sandbox/cache-residency/objects/.owner.lock
      touch /var/lib/aos/sandbox/cache-residency/objects/owner-state
      chmod 0600 /var/lib/aos/sandbox/cache-residency/objects/.owner.lock
      chmod 0600 /var/lib/aos/sandbox/cache-residency/objects/owner-state
      chown 811:811 /var/lib/aos/sandbox/cache-residency/objects/.owner.lock
      chown 811:811 /var/lib/aos/sandbox/cache-residency/objects/owner-state

      ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        ${policyCutProbe}/bin/aos-sandbox-policy-cut-negative-probe
      ${cacheDacProbe}/bin/aos-sandbox-cache-dac-negative-probe
    '';
  }

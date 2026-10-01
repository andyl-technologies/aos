# Evaluation contract for public-only production image finalization inputs.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fixtureAuthorities = {pkgs, ...}: {
    aos.profiles.canonicalRelease = {
      enable = true;
      publicAuthorities = {
        secureBootCertificate = "${pkgs.secure-boot-test-keys}/db.crt";
        moduleSigningCertificate = "${pkgs.secure-boot-test-keys}/modsign.crt";
        pcrPolicyKey = "${pkgs.secure-boot-test-keys}/pcr.pem";
        firmwareEnrollment = "${pkgs.secure-boot-test-keys}";
      };
    };
  };
  system = mkSystem {
    modules = [../../systems/server.nix fixtureAuthorities];
    systemName = "release-variant-fixture";
  };
  secureBoot = system.config.aos.boot.secureBoot;
  assembly = system.config.system.build.unsignedImageAssembly;
  imageMatrix = (import ../../lib/testing/image-matrix.nix {inherit pkgs lib;}) {
    sourceIdentity = "unused-evaluation-fixture";
    systems = {
      external = {
        config = system.config;
        build = {
          unsignedImageAssembly = assembly;
          image = throw "external assemblies have no locally signed image formats";
        };
      };
      local = {
        config.aos.boot.secureBoot.externalFinalization.enable = false;
        build.image = lib.genAttrs ["qcow2" "raw" "vhd" "vmdk"] (_: null);
      };
    };
  };
in
  assert secureBoot.dbKey == null;
  assert secureBoot.lockdown.moduleSigningKey == null;
  assert secureBoot.measuredBoot.pcrPrivateKey == null;
  assert secureBoot._effectiveDbCert != secureBoot.dbCert;
  assert secureBoot.lockdown._effectiveModuleSigningCert != secureBoot.lockdown.moduleSigningCert;
  assert secureBoot.measuredBoot._effectivePcrPublicKey != secureBoot.measuredBoot.pcrPublicKey;
  assert secureBoot._effectiveEnrollAuthDir != secureBoot.enrollAuthDir;
  assert system.config.aos.security.level == "hardened";
  assert !system.config.aos.security.selinux.enable;
  assert assembly != null;
  assert builtins.attrNames imageMatrix.systems == ["local"];
  assert builtins.attrNames imageMatrix.assemblies == ["external"];
  assert imageMatrix.assemblies.external.drvPath == assembly.drvPath;
  # The release plan uses the discovered variant, not the shared OS name.
  assert system.config.aos.system.name != "release-variant-fixture";
  assert lib.hasInfix "--arg variant 'release-variant-fixture'" (builtins.head assembly.passthru.phases).script;
    pkgs.mkDerivation {
      pname = "external-image-assembly-evaluation-check";
      version = "0";
      src = null;
      preferLocalBuild = true;
      allowSubstitutes = false;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<'EOF'
            public-private-options=absent
            public-authorities=image-fixed
            assembly=${builtins.unsafeDiscardStringContext assembly.drvPath}
            platform=${lib.system}
            EOF
          '';
        }
      ];
    }

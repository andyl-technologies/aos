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
  };
  secureBoot = system.config.aos.boot.secureBoot;
  assembly = system.config.system.build.unsignedImageAssembly;
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

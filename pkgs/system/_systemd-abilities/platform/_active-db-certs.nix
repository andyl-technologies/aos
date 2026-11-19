##! Builds the PEM bundle of every Secure Boot db certificate the image accepts.
#
# The bundle holds the image's own signing certificate followed by every
# rotation-overlap certificate published by a configured registry. Recovery,
# the immutable root, and installer media all authenticate release artifacts
# against this exact set.
{
  pkgs,
  lib,
  config,
}: let
  sb = config.aos.boot.secureBoot;
  registryCertificates = lib.concatLists (
    map
    (registry: registry.sbDbCerts)
    (builtins.attrValues config.aos.apm.registries)
  );
  registryCertificateFiles =
    lib.imap
    (index: certificate:
      pkgs.writeTextFile {
        name = "aos-recovery-active-db-${toString index}";
        destination = "/certificate.pem";
        text = certificate;
      })
    registryCertificates;
in
  if sb.enable
  then
    pkgs.mkDerivation {
      pname = "aos-recovery-active-db-certs";
      version = "1";
      src = null;
      buildDeps = [pkgs.coreutils];
      runtimeDeps = [];
      propagatedDeps = [];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p $out
            cp ${sb._effectiveDbCert} $out/active-db-certs.pem
            chmod u+w $out/active-db-certs.pem
            ${lib.concatMapStringsSep "\n" (certificate: ''
                printf '\n' >> $out/active-db-certs.pem
                cat ${certificate}/certificate.pem >> $out/active-db-certs.pem
              '')
              registryCertificateFiles}
          '';
        }
      ];
    }
  else null

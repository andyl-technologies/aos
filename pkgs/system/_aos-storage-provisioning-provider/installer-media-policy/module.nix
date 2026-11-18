##! Selects unattended installation in the initrd of AOS installer media.
#
# Installer media carries no immutable root or persistent state, so the
# installed-system boot effects are absent and first-boot provisioning is
# replaced by installation. The package output holds the db certificates that
# authorize the release payload.
{package, ...}: {
  aos.boot.installerMedia = true;
  aos.storageProvisioning.enable = false;
  aos.installer = {
    enable = true;
    trustBundle = "${package}/active-db-certs.pem";
  };
}

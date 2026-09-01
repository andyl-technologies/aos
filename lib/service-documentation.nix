##! lib/service-documentation.nix - canonical service configuration ownership.
##!
##! This closed Nix value is bundled into every evaluation base library. The
##! package publisher uses it to associate image-owned configuration options
##! with the package that implements the service, without turning those
##! options into a competing package-owned runtime module.
##!
##! `package` entries are covered by their signed config-module companion.
##! `system` entries select option prefixes from the exact image base library
##! and describe the systemd units implemented by that package. `platform`
##! covers the complete AOS image option surface.
{
  schema = "aos.service-documentation/v1";

  services = {
    aos = {
      ownership = "platform";
      optionPrefixes = [];
      units = [
        "aos-attest.service"
        "aos-eval.service"
        "aos-firstboot-reeval.service"
        "aos-host-config-cache.service"
        "aos-host-config-restore.service"
        "aos-image-boot-commit.service"
        "aos-install-baked-packages.service"
        "aos-nix-db.service"
        "aos-provisioning-persist.service"
        "aos-registry-sync.service"
      ];
    };

    aos-hub = {
      ownership = "system";
      optionPrefixes = ["aos.registry-hub"];
      units = ["aos-hub.service"];
    };

    audit = {
      ownership = "system";
      optionPrefixes = ["aos.security.audit"];
      units = ["audit-rules.service" "auditd.service"];
    };

    chrony = {
      ownership = "system";
      optionPrefixes = ["aos.services.chrony"];
      units = ["chronyd.service"];
    };

    dbus = {
      ownership = "system";
      optionPrefixes = ["aos.services.dbus"];
      units = ["dbus.service" "dbus.socket"];
    };

    openssh = {
      ownership = "system";
      optionPrefixes = ["aos.services.ssh"];
      units = ["aos-ssh-ready.service" "sshd-keygen.service" "sshd.service"];
    };

    smartmontools = {
      ownership = "system";
      optionPrefixes = ["aos.monitoring.hardware"];
      units = ["smartd.service"];
    };

    nftables = {
      ownership = "system";
      optionPrefixes = ["aos.firewall"];
      units = ["nftables.service"];
    };

    systemd = {
      ownership = "system";
      optionPrefixes = ["aos.networking" "boot.initrd.systemd" "systemd"];
      units = [
        "systemd-networkd.service"
        "systemd-resolved.service"
      ];
    };

    aos-registry-server.ownership = "package";
    cilium.ownership = "package";
    cloudcore.ownership = "package";
    conntrack-tools.ownership = "package";
    containerd.ownership = "package";
    edgecore.ownership = "package";
    envoy.ownership = "package";
    etcd.ownership = "package";
    garage.ownership = "package";
    k3s-combined.ownership = "package";
    k3s-control-plane.ownership = "package";
    k3s-worker.ownership = "package";
    krb5.ownership = "package";
    longhorn-manager.ownership = "package";
    mariadb.ownership = "package";
    nginx.ownership = "package";
    openldap.ownership = "package";
    postgresql.ownership = "package";
    rsync.ownership = "package";
  };
}

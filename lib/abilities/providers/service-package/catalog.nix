##! Production services migrated from expose-driven lifecycle to ability effects.
{
  cloudcore = {
    interface = "aos.service.cloudcore";
    units = [
      "cloudcore.service"
      "aos-pkg-cloudcore-firewall.service"
      "aos-pkg-cloudcore-mac.service"
      "aos-pkg-cloudcore-modules.service"
      "aos-pkg-cloudcore-service-roots.service"
      "aos-pkg-cloudcore-sysctl.service"
    ];
  };
  conntrack-tools = {
    interface = "aos.service.conntrack-tools";
    units = [
      "conntrackd.service"
      "aos-pkg-conntrack-tools-firewall.service"
      "aos-pkg-conntrack-tools-mac.service"
      "aos-pkg-conntrack-tools-modules.service"
      "aos-pkg-conntrack-tools-service-roots.service"
      "aos-pkg-conntrack-tools-sysctl.service"
    ];
  };
  containerd = {
    interface = "aos.service.containerd";
    units = [
      "containerd.service"
      "aos-pkg-containerd-firewall.service"
      "aos-pkg-containerd-host-paths.service"
      "aos-pkg-containerd-modules.service"
      "aos-pkg-containerd-sysctl.service"
    ];
  };
  edgecore = {
    interface = "aos.service.edgecore";
    units = [
      "edgecore.service"
      "aos-pkg-edgecore-firewall.service"
      "aos-pkg-edgecore-host-paths.service"
      "aos-pkg-edgecore-modules.service"
      "aos-pkg-edgecore-sysctl.service"
    ];
  };
  envoy = {
    interface = "aos.service.envoy";
    units = [
      "envoy.service"
      "aos-pkg-envoy-firewall.service"
      "aos-pkg-envoy-mac.service"
      "aos-pkg-envoy-modules.service"
      "aos-pkg-envoy-service-roots.service"
      "aos-pkg-envoy-sysctl.service"
    ];
  };
  etcd = {
    interface = "aos.service.etcd";
    units = [
      "etcd.service"
      "aos-pkg-etcd-firewall.service"
      "aos-pkg-etcd-mac.service"
      "aos-pkg-etcd-modules.service"
      "aos-pkg-etcd-service-roots.service"
      "aos-pkg-etcd-sysctl.service"
    ];
  };
  garage = {
    interface = "aos.service.garage";
    units = [
      "garage-prepare.service"
      "garage.service"
      "aos-pkg-garage-firewall.service"
      "aos-pkg-garage-mac.service"
      "aos-pkg-garage-modules.service"
      "aos-pkg-garage-service-roots.service"
      "aos-pkg-garage-sysctl.service"
    ];
  };
  krb5 = {
    interface = "aos.service.krb5";
    units = [
      "krb5-kdc-init.service"
      "krb5-kdc.service"
      "kadmind.service"
      "aos-pkg-krb5-firewall.service"
      "aos-pkg-krb5-mac.service"
      "aos-pkg-krb5-modules.service"
      "aos-pkg-krb5-service-roots.service"
      "aos-pkg-krb5-sysctl.service"
    ];
  };
  kubelet = {
    interface = "aos.service.kubelet";
    units = [
      "kubelet.service"
      "aos-pkg-kubelet-firewall.service"
      "aos-pkg-kubelet-host-paths.service"
      "aos-pkg-kubelet-modules.service"
      "aos-pkg-kubelet-sysctl.service"
    ];
  };
  mariadb = {
    interface = "aos.service.mariadb";
    units = [
      "mariadb-init.service"
      "mariadb.service"
      "aos-pkg-mariadb-firewall.service"
      "aos-pkg-mariadb-mac.service"
      "aos-pkg-mariadb-modules.service"
      "aos-pkg-mariadb-service-roots.service"
      "aos-pkg-mariadb-sysctl.service"
    ];
  };
  openldap = {
    interface = "aos.service.openldap";
    units = [
      "openldap.service"
      "aos-pkg-openldap-firewall.service"
      "aos-pkg-openldap-mac.service"
      "aos-pkg-openldap-modules.service"
      "aos-pkg-openldap-service-roots.service"
      "aos-pkg-openldap-sysctl.service"
    ];
  };
  rsync = {
    interface = "aos.service.rsync";
    units = [
      "rsyncd.service"
      "aos-pkg-rsync-firewall.service"
      "aos-pkg-rsync-mac.service"
      "aos-pkg-rsync-modules.service"
      "aos-pkg-rsync-service-roots.service"
      "aos-pkg-rsync-sysctl.service"
    ];
  };
}

##! Current service-manager mapping from logical package services to units.
{
  cloudcore.main = "cloudcore.service";
  conntrack-tools.main = "conntrackd.service";
  containerd.main = "containerd.service";
  edgecore.main = "edgecore.service";
  envoy.main = "envoy.service";
  etcd.main = "etcd.service";
  garage = {
    prepare = "garage-prepare.service";
    main = "garage.service";
  };
  krb5 = {
    initialize = "krb5-kdc-init.service";
    kdc = "krb5-kdc.service";
    administration = "kadmind.service";
  };
  kubelet.main = "kubelet.service";
  mariadb = {
    initialize = "mariadb-init.service";
    main = "mariadb.service";
  };
  openldap.main = "openldap.service";
  rsync.main = "rsyncd.service";
}

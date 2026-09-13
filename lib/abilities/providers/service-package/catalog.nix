##! Logical service declarations for production package lifecycle providers.
let
  commonFeatures = [
    "configuration"
    "identity"
    "isolation"
    "readiness"
    "storage"
    "supervision"
  ];
  single = interface: {
    inherit interface;
    services = [
      {
        key = "main";
        dependencies = [];
      }
    ];
    methods = ["observe" "restart" "start" "stop"];
    features = commonFeatures;
  };
in {
  cloudcore = single "aos.service.cloudcore";
  conntrack-tools = single "aos.service.conntrack-tools";
  containerd = single "aos.service.containerd";
  edgecore = single "aos.service.edgecore";
  envoy = single "aos.service.envoy";
  etcd = single "aos.service.etcd";
  garage =
    (single "aos.service.garage")
    // {
      services = [
        {
          key = "prepare";
          dependencies = [];
        }
        {
          key = "main";
          dependencies = ["prepare"];
        }
      ];
      features = commonFeatures ++ ["dependencies"];
    };
  krb5 =
    (single "aos.service.krb5")
    // {
      services = [
        {
          key = "initialize";
          dependencies = [];
        }
        {
          key = "kdc";
          dependencies = ["initialize"];
        }
        {
          key = "administration";
          dependencies = ["initialize"];
        }
      ];
      features = commonFeatures ++ ["dependencies"];
    };
  kubelet = single "aos.service.kubelet";
  mariadb =
    (single "aos.service.mariadb")
    // {
      services = [
        {
          key = "initialize";
          dependencies = [];
        }
        {
          key = "main";
          dependencies = ["initialize"];
        }
      ];
      features = commonFeatures ++ ["dependencies"];
    };
  openldap = single "aos.service.openldap";
  rsync = single "aos.service.rsync";
}

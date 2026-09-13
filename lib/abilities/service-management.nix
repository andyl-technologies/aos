##! Canonical manager-neutral service lifecycle and feature identities.
{
  schemas,
  guarantee,
}: let
  features = {
    configuration = guarantee {
      name = "aos.service.feature.configuration";
      version = 1;
      descriptor = "sha256:795691e4da6ad4983fdcdee83ce3241f00b880a7a75e9f8c8c1292ed10d02728";
    };
    credentials = guarantee {
      name = "aos.service.feature.credentials";
      version = 1;
      descriptor = "sha256:9b691f3825a27d582ab9d68848ef6733c8daff6591af5d5aefb1ed1b33ca5731";
    };
    dependencies = guarantee {
      name = "aos.service.feature.dependencies";
      version = 1;
      descriptor = "sha256:d41d1c135639c9c64f9c2c3fd14f5155e27e69f815a50cc36070c46972ab5791";
    };
    identity = guarantee {
      name = "aos.service.feature.identity";
      version = 1;
      descriptor = "sha256:428c991097b18a0e43ee19bc799ce735986567f7934f5c148d39c485efd1406c";
    };
    isolation = guarantee {
      name = "aos.service.feature.isolation";
      version = 1;
      descriptor = "sha256:4890b6ca323060f281a98fd49f290ac081d9acefc9fc23e02c8981759ef3f86d";
    };
    readiness = guarantee {
      name = "aos.service.feature.readiness";
      version = 1;
      descriptor = "sha256:8db2fc4868b442bf71a5658db9ccb181fa928029d26411d7aafa6d1cac77e3de";
    };
    reload = guarantee {
      name = "aos.service.feature.reload";
      version = 1;
      descriptor = "sha256:1af6c5b5bef1339644a7ce8b02524728c6ed266fc634c3d62b5ebd1e695172a8";
    };
    storage = guarantee {
      name = "aos.service.feature.storage";
      version = 1;
      descriptor = "sha256:b35dbbe867ce562df3efdaa7a17b7a61169df4fa0ef4dd19c76203b48b697704";
    };
    supervision = guarantee {
      name = "aos.service.feature.supervision";
      version = 1;
      descriptor = "sha256:634cf62951642871683e93d7fc1df90b378610563955d13781d26b7a5fd91b9f";
    };
  };
in {
  interface = {
    name = "aos.service-management";
    abi = 1;
    descriptor = "sha256:a51e8ccfbde3b8caa89120afdd033edfaa51f087ffc399c3aa3006f34e6c0dff";
  };
  inherit features;
  featureNames = builtins.attrNames features;
  featureGuarantees = names: builtins.map (name: features.${name}) names;
  requestSchema = schemas.boolean;
  methods = ["observe" "reload" "restart" "start" "stop"];
  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
}

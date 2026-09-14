##! Host identities and directories owned by the PostgreSQL ability provider.
{lib}: let
  slots = lib.range 0 63;
  suffix = slot:
    if slot < 10
    then "0${toString slot}"
    else toString slot;
  providerName = slot: "aos-ability-pg-${suffix slot}";
  probeName = slot: "aos-ability-pg-probe-${suffix slot}";
  brokerName = slot: "aos-ability-pg-broker-${suffix slot}";

  providerUsers = builtins.listToAttrs (map (slot: {
      name = providerName slot;
      value = {
        uid = 7100 + slot;
        group = "aos-ability-postgresql";
        home = "/var/lib/aos/ability-runtime/postgresql";
        shell = "/sbin/nologin";
        description = "AOS native PostgreSQL provider slot ${toString slot}";
        extraGroups = [];
      };
    })
    slots);
  probeUsers = builtins.listToAttrs (map (slot: {
      name = probeName slot;
      value = {
        uid = 7200 + slot;
        group = probeName slot;
        home = "/var/empty";
        shell = "/sbin/nologin";
        description = "AOS native PostgreSQL probe slot ${toString slot}";
        extraGroups = [];
      };
    })
    slots);
  brokerUsers = builtins.listToAttrs (map (slot: {
      name = brokerName slot;
      value = {
        uid = 7300 + slot;
        group = probeName slot;
        home = "/var/empty";
        shell = "/sbin/nologin";
        description = "AOS native PostgreSQL endpoint broker slot ${toString slot}";
        extraGroups = [];
      };
    })
    slots);
  probeGroups = builtins.listToAttrs (map (slot: {
      name = probeName slot;
      value = {
        gid = 7200 + slot;
        members = [];
      };
    })
    slots);
in {
  users = providerUsers // probeUsers // brokerUsers;
  groups =
    probeGroups
    // {
      aos-ability-postgresql = {
        gid = 71;
        members = [];
      };
    };
  tmpfiles = ''
    d /var/lib/aos/ability-runtime/postgresql 0710 root aos-ability-postgresql -
    d /run/aos-ability-postgresql             0711 root root                   -
    ${lib.concatMapStringsSep "\n" (slot: "d /run/aos-ability-postgresql/${suffix slot} 2710 ${providerName slot} ${probeName slot} -") slots}
  '';
  artifacts = {
    users = builtins.attrNames (providerUsers // probeUsers // brokerUsers);
    groups = builtins.attrNames (
      probeGroups
      // {aos-ability-postgresql = {};}
    );
    etc = ["tmpfiles.d/aos-ability-postgresql.conf"];
  };
}

##! Declares the native filesystem allocations used by AOS package runtime.
{
  config,
  lib,
  ...
}: let
  host = (config.aos.boot.stage or "host") == "host";
  privateRoot = "/var/lib/aos/ability-runtime";
  privateParent = config.aos.abilities.filesystem.operations.persistentAllocate.effects."aos-runtime-var-lib-aos-ability-runtime".outputs.resource;
  directory = path: mode: {
    enable = host;
    inherit path mode;
    owner = "root";
    group = "root";
    persistent = lib.hasPrefix "/var/" path;
  };
  privateChild = name: mode:
    directory "${privateRoot}/${name}" mode // {parentResource = privateParent;};
in {
  # Bootstrap service directories own APM and attestation state. The image or
  # operator configuration owns /etc/aos/packages.d; these effects own only
  # private runtime allocations and must not adopt those existing directories.
  aos.directories = {
    "aos-runtime-var-lib-aos-ability-runtime" = directory privateRoot "0711";
    "aos-runtime-var-lib-aos-ability-runtime-credential-sources" = privateChild "credential-sources" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-credentials" = privateChild "credentials" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-endpoints" = privateChild "endpoints" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-network-policy" = privateChild "network-policy" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-storage" = privateChild "storage" "0711";
    "aos-runtime-run-apm" = directory "/run/apm" "0700";
  };
}

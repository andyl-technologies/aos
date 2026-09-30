##! Declares the native filesystem allocations used by AOS package runtime.
{
  config,
  lib,
  ...
}: let
  host = (config.aos.boot.stage or "host") == "host";
  directory = path: mode: {
    enable = host;
    inherit path mode;
    owner = "root";
    group = "root";
    persistent = lib.hasPrefix "/var/" path;
  };
in {
  aos.directories = {
    "aos-runtime-var-lib-aos-ability-runtime" = directory "/var/lib/aos/ability-runtime" "0711";
    "aos-runtime-var-lib-aos-ability-runtime-credential-sources" = directory "/var/lib/aos/ability-runtime/credential-sources" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-credentials" = directory "/var/lib/aos/ability-runtime/credentials" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-endpoints" = directory "/var/lib/aos/ability-runtime/endpoints" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-network-policy" = directory "/var/lib/aos/ability-runtime/network-policy" "0700";
    "aos-runtime-var-lib-aos-ability-runtime-storage" = directory "/var/lib/aos/ability-runtime/storage" "0711";
    "aos-runtime-etc-aos-packages.d" = directory "/etc/aos/packages.d" "0755";
    "aos-runtime-run-apm" = directory "/run/apm" "0700";
    "aos-runtime-run-aos-attest" = directory "/run/aos-attest" "0700";
    "aos-runtime-var-lib-apm" = directory "/var/lib/apm" "0755";
    "aos-runtime-var-lib-apm-config" = directory "/var/lib/apm/config" "0755";
    "aos-runtime-var-lib-apm-config-registries.d" = directory "/var/lib/apm/config/registries.d" "0755";
  };
}

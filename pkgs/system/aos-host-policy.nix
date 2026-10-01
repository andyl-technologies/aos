##! Portable native system policy retained for profile reconfiguration.
{
  mkDerivation,
  coreutils,
  bash,
  kmod,
  aos-kernel-tunable-provider,
  service-management,
  aos-configuration-lower,
  aos-metadata-provider,
  ca-certificates,
  glibc-locales,
}:
mkDerivation {
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = ["x86_64" "aarch64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };
  pname = "aos-host-policy";
  version = "1";
  module = ./_aos-host-policy;
  moduleDeps = [kmod aos-kernel-tunable-provider service-management aos-configuration-lower aos-metadata-provider glibc-locales];
  runtimeDeps = [coreutils bash ca-certificates];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
      '';
    }
  ];
  meta.description = "Replayable kernel and networking system policy";
}

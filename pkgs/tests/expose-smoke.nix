{
  mkDerivation,
  bash,
}:
mkDerivation {
  pname = "expose-smoke";
  version = "0";
  src = null;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/expose-smoke"
        echo "payload" > "$out/share/expose-smoke/payload.txt"
      '';
    }
  ];

  expose = {
    units."expose-smoke.service" = {
      description = "RFC-0001 expose smoke service";
      wantedBy = ["aos-pkg-expose-smoke.target"];
      after = ["network.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${bash}/bin/bash -c true";
      };
    };
    units."var-lib-exposesmoke.mount" = {
      description = "RFC-0001 expose smoke mount";
      wantedBy = ["aos-pkg-expose-smoke.target"];
      what = "tmpfs";
      where = "/var/lib/exposesmoke";
      type = "tmpfs";
      mountConfig.Options = "mode=0755";
    };
    permissions = {
      network = "private";
      capabilities = [];
      devices = [];
      host-paths = [];
      kernel-modules = [];
      syscalls = "restricted";
      security-label = "aos.expose-smoke";
    };
    requires = [];
  };

  meta.description = "RFC-0001 package expose renderer smoke test payload";
}

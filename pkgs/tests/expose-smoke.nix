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
      wantedBy = ["multi-user.target"];
      requiredBy = ["multi-user.target"];
      upheldBy = ["multi-user.target"];
      after = ["network.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${bash}/bin/bash -c true";
      };
    };
    units."var-lib-exposesmoke.mount" = {
      description = "RFC-0001 expose smoke mount";
      wantedBy = ["multi-user.target"];
      what = "tmpfs";
      where = "/var/lib/exposesmoke";
      type = "tmpfs";
      mountConfig.Options = "mode=0755";
    };
    kernel = {
      modules = ["br_netfilter"];
      sysctl."net.ipv4.ip_forward" = "1";
    };
    firewall = {
      allowedTCP = [8000 8443];
      allowedUDP = [5353];
      forwardPolicy = "accept";
    };
    permissions = {
      network = "private";
      capabilities = [];
      devices = [];
      host-paths = [];
      kernel-modules = ["br_netfilter"];
      syscalls = "restricted";
      security-label = "aos.expose-smoke";
    };
  };

  meta = {
    description = "Package expose renderer smoke test payload";
    license = "Apache-2.0";
  };
}

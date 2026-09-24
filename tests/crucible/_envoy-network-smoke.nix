{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-envoy-network-smoke";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.curl
    pkgs.envoy
    pkgs.nginx
  ];
  runtimeDeps = [];

  phases = [
    {
      name = "check-routed-service";
      script = ''
        RENDER_ENVOY=${./fixtures/envoy-network/render-envoy.sh} \
          ${pkgs.bash}/bin/bash ${./fixtures/envoy-network/smoke.sh}
      '';
    }
  ];
}

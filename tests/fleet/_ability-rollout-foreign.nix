##! Defines the independent service observed during image rollout flights.
{pkgs}: let
  service = {
    description = "Disposable foreign unit for rollout effect qualification";
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
  };
in {
  module.systemd.services.aos-rollout-matrix-foreign = service;

  hostModule = ''
    systemd.services.aos-rollout-matrix-foreign = builtins.fromJSON ${builtins.toJSON (builtins.toJSON service)};
  '';
}

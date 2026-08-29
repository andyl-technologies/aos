{
  lib,
  pkgs,
  generation,
}: let
  isGen2 = generation == 2;

  httpService = {
    description = "Upgrade fixture HTTP server on :8000";
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind 0.0.0.0 8000";
      WorkingDirectory = "%S";
      StateDirectory = "test-http-server";
      Restart = "on-failure";
      DynamicUser = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
    };
  };
in {
  assertions = [
    {
      assertion = generation == 1 || generation == 2;
      message = "upgrade HTTP fixture generation must be 1 or 2";
    }
  ];

  # This module exists only to exercise image-generation reconciliation. Its
  # Python HTTP server is therefore an explicit test artifact, never part of
  # the production server image contract.
  aos.image.allowTestArtifacts = true;
  aos.image.testArtifactRoots = [pkgs.python3];

  environment.systemPackages = [pkgs.python3];

  aos.firewall.allowedTCP = [8000] ++ lib.optional isGen2 8443;
  aos.kernel.sysctl = lib.mkIf isGen2 {
    "net.ipv4.tcp_keepalive_time" = "300";
  };

  systemd.services =
    {
      test-http-server = httpService;
    }
    // (
      if isGen2
      then {
        aos-upgrade-test-marker = {
          description = "Upgrade-test marker oneshot";
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.coreutils}/bin/true";
            RemainAfterExit = true;
          };
        };
      }
      else {
        aos-upgrade-removed = {
          description = "Upgrade-test removed oneshot";
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.coreutils}/bin/true";
            ExecStop = "${pkgs.coreutils}/bin/touch /run/removed-stop-ran";
            RemainAfterExit = true;
          };
        };
      }
    );
}

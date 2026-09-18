##! lib/testing/sandbox-network-broker.nix — Network broker deployment contract
{
  lib,
  pkgs,
  mkSystem,
}: let
  controllerUid = 1811;
  controllerGid = 1812;
  system = mkSystem {
    modules = [
      ../../systems/server.nix
      {
        aos.sandbox = {
          controller = {
            uid = controllerUid;
            gid = controllerGid;
          };
          networkBroker.enable = true;
        };
      }
    ];
    systemName = "sandbox-network-broker-check";
  };
  socket = system.config.systemd.sockets.aos-netd;
  service = system.config.systemd.services.aos-netd;
  socketConfig = socket.socketConfig;
  serviceConfig = service.serviceConfig;
  socketUnit = system.config.systemd.units."aos-netd.socket".text;
  serviceUnit = system.config.systemd.units."aos-netd.service".text;
  requiredSocketLines = [
    "Accept=false"
    "PassCredentials=true"
    "PassPIDFD=true"
  ];
  forbiddenServiceCapabilities = [
    "AmbientCapabilities=CAP_NET_ADMIN"
    "CapabilityBoundingSet=CAP_NET_ADMIN"
  ];
  containsEvery = text: lines:
    builtins.all (line: lib.hasInfix line text) lines;
  containsNone = text: lines:
    builtins.all (line: !(lib.hasInfix line text)) lines;
  passed =
    socketConfig.ListenSequentialPacket
    == "/run/aos/sandbox-network/control.sock"
    && socketConfig.FileDescriptorName == "aos-netd"
    && socketConfig.Service == "aos-netd.service"
    && socketConfig.SocketUser == "aos-sandboxd"
    && socketConfig.SocketGroup == "aos-sandboxd"
    && socketConfig.SocketMode == "0600"
    && socketConfig.DirectoryMode == "0710"
    && socketConfig.SendBuffer == "4M"
    && serviceConfig.ExecStart
    == "${pkgs.aos-netd}/bin/aos-netd ${toString controllerUid} ${toString controllerGid}"
    && serviceConfig.StateDirectory == "aos/sandbox-network"
    && serviceConfig.RuntimeDirectory == "aos/sandbox-pins/netns"
    && serviceConfig.CapabilityBoundingSet == ""
    && serviceConfig.NoNewPrivileges
    && serviceConfig.PrivateNetwork
    && serviceConfig.ProtectControlGroups
    && serviceConfig.ProtectSystem == "strict"
    && serviceConfig.RestrictAddressFamilies == ["AF_UNIX"]
    && serviceConfig.RestrictNamespaces
    && serviceConfig.Slice == "aos-control.slice"
    && containsEvery socketUnit requiredSocketLines
    && containsNone serviceUnit forbiddenServiceCapabilities;
in
  if !passed
  then throw "sandbox Network broker deployment contract failed"
  else
    pkgs.runCommand "sandbox-network-broker-module-check" {} ''
      mkdir -p $out
      echo PASS > $out/result
    ''

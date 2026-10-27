##! Orders identity-owned sockets after native host activation.
{
  config,
  lib,
}: let
  activationUnit =
    if config.aos.config.unitGraph.enable or false
    then "aos-activate.service"
    else if config.aos.boot.substrateServices.handoffEnabled or false
    then "aos-ability-host-controller.service"
    else null;

  # Host activation may itself need basic.target and the early socket set.
  # Identity-owned sockets therefore join multi-user.target after activation,
  # with their normal shutdown ordering stated explicitly.
  module = lib.mkIf (activationUnit != null) {
    wantedBy = lib.mkForce ["multi-user.target"];
    requires = [activationUnit];
    after = [activationUnit];
    before = ["multi-user.target" "shutdown.target"];
    conflicts = ["shutdown.target"];
    unitConfig.DefaultDependencies = false;
  };
in {
  inherit module;

  apply = socket: lib.mkMerge [socket module];
}

##! Selects the exact shared Controller, Root and signer image artifact.
{
  config,
  pkgs,
}:
if config.aos.sandbox.nixBroker.enable or false
then
  pkgs.aosNixOnlineControllerWith {
    domainIdHex =
      if config.aos.sandbox.nixBroker.domainIdHex == null
      then throw "online Resolve50 requires an explicit nonzero domain16"
      else config.aos.sandbox.nixBroker.domainIdHex;
  }
else pkgs.aos-sandboxd

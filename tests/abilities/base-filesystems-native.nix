##! Checks encrypted swap composition through native block-storage resources.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-filesystems";
    module = ../../modules/base/filesystems.nix;
    packages = [
      pkgs.systemd
      pkgs.cryptsetup
      pkgs.aos-cryptsetup-provider
      pkgs.aos-storage-format-provider
    ];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  resultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
in
  assert requests."cryptsetup:swap-device".parameters.device == "/dev/disk/by-partlabel/swap";
  assert requests."cryptsetup:encrypted-swap-mapping".parameters.source
  == resultOf "cryptsetup:swap-device" "device-node";
  assert requests."cryptsetup:encrypted-swap-format".parameters.policy == "always";
  assert requests."cryptsetup:encrypted-swap-format".parameters.source
  == resultOf "cryptsetup:encrypted-swap-mapping" "mapped-device";
  assert requests."cryptsetup:encrypted-swap".parameters.source
  == resultOf "cryptsetup:encrypted-swap-format" "formatted-path";
  assert !(config.systemd.services ? cryptswap); true

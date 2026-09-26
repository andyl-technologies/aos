##! Provider-neutral event-log policy and systemd rendering checks.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "event-log-policy";
    module = ../../modules/base/journald.nix;
    packages = [pkgs.systemd];
  };
  request = evaluated.config.aos.abilities.requests."aos:event-log-policy";
  rendered = import ../../pkgs/system/_systemd-abilities/platform/_event-log-configuration.nix {
    policy = request.parameters;
  };
in
  assert request.parameters
  == {
    storage = "persistent";
    max_retention_seconds = 2592000;
    max_use_bytes = 524288000;
    max_file_bytes = 52428800;
    rate_limit_interval_millis = 30000;
    rate_limit_burst = 10000;
    forward_to_syslog = false;
    compress = true;
  };
  assert request.requirement == "aos:event-log-policy";
  assert request.lifetime == "instance";
  assert evaluated.config.aos.abilities.implementations."systemd:event-log-policy".interface
  == lib.abilities.interfaces.eventLogPolicy.interface.identity;
  assert !(evaluated.config.environment.etc ? "systemd/journald.conf");
  assert lib.hasInfix "Storage=persistent" rendered."systemd/journald.conf".text;
  assert lib.hasInfix "MaxRetentionSec=2592000s" rendered."systemd/journald.conf".text;
  assert lib.hasInfix "SystemMaxUse=524288000" rendered."systemd/journald.conf".text;
  assert rendered ? "tmpfiles.d/aos-event-log.conf"; true

##! Focused package check for the native nginx ability module.
{pkgs, ...}: let
  contract =
    (pkgs.nginx.checks {
      testing = {};
      self = pkgs.nginx;
      inherit pkgs;
    }).ability-contract;
in
  pkgs.runCommand "nginx-config-module-check" {} ''
    test -s ${contract}/result
    mkdir -p "$out"
    printf '%s\n' PASS >"$out/result"
  ''

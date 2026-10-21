##! Checks immutable initrd inputs and the actual provider-rendered file tree.
{
  lib,
  pkgs,
}: let
  renderer = ../../pkgs/system/_systemd-abilities/platform/_initrd-configuration.nix;
  input = path: {
    inherit path;
    content = "immutable configuration\n";
    fragments = [];
    format = "text";
    value = null;
    owner = null;
    group = null;
    mode = "0444";
  };
  effect = name: value: {
    enable = true;
    input = value;
    contract.identity = ["test" "initrd" "configuration" "file" name];
  };
  inputs = effects:
    (import renderer {
      inherit lib effects;
      runCommand = _: attributes: _: attributes;
      jq = "/nix/store/00000000000000000000000000000000-jq";
      configurationProvider = "/nix/store/00000000000000000000000000000000-provider";
    }).configurationJSON;
  rejected = effects: !(builtins.tryEval (inputs effects)).success;
  fixtures = {
    text = effect "text" ((input "/etc/test/plain.conf") // {owner = "root";});
    json = effect "json" ((input "/etc/test/data.json")
      // {
        content = null;
        format = "json";
        value = {enabled = true;};
      });
    toml = effect "toml" ((input "/etc/test/data.toml")
      // {
        content = null;
        format = "toml";
        value = {enabled = true;};
      });
    runtime = effect "runtime" (input "/run/aos/runtime-only.conf");
    disabled = (effect "disabled" (input "/etc/test/disabled.conf")) // {enable = false;};
  };
  rendered = import renderer {
    inherit lib;
    inherit (pkgs) runCommand;
    jq = pkgs.buildPackages.jq;
    configurationProvider = pkgs.buildPackages.aos-configuration-provider;
    effects = fixtures;
  };
in {
  checks = {
    selectsOnlyEnabledEtcFiles = builtins.length (builtins.fromJSON (inputs fixtures)) == 3;
    rejectsTraversal = rejected {bad = effect "bad" (input "/etc/test/../escape");};
    rejectsLineBreak = rejected {bad = effect "bad" (input "/etc/test/line\nbreak");};
    rejectsForeignIdentity = rejected {bad = effect "bad" ((input "/etc/test/file") // {owner = "daemon";});};
    rejectsRuntimeCredentials = rejected {
      bad = effect "bad" ((input "/etc/test/file")
        // {
          content = null;
          fragments = [
            {
              credentialPath = "/run/credentials/secret";
              maximumBytes = 32;
            }
          ];
        });
    };
    rejectsDuplicateDestinations = rejected {
      first = effect "first" (input "/etc/test/file");
      second = effect "second" (input "/etc/test/file");
    };
  };
  serialization = pkgs.runCommand "aos-initrd-configuration-serialization" {} ''
    test "$(cat ${rendered}/etc/test/plain.conf)" = 'immutable configuration'
    ${pkgs.jq}/bin/jq -e '.enabled == true' ${rendered}/etc/test/data.json > /dev/null
    test "$(cat ${rendered}/etc/test/data.toml)" = '"enabled" = true'
    test "$(stat -c %a ${rendered}/etc/test/plain.conf)" = 444
    test ! -e ${rendered}/run
    test ! -e ${rendered}/etc/test/disabled.conf
    mkdir -p "$out"
    echo PASS > "$out/result"
  '';
}

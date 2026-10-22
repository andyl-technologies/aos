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
    input = value;
    identity = ["test" "initrd" "@environment" "configuration" "file" name];
  };
  inputs = nodes:
    (import renderer {
      inherit lib nodes;
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
    writableMode = effect "writable-mode" ((input "/etc/test/mode.conf") // {mode = "0640";});
    runtime = effect "runtime" (input "/run/aos/runtime-only.conf");
    otherOperation =
      (effect "other" (input "/etc/test/other.conf"))
      // {
        identity = ["test" "initrd" "@environment" "other" "file" "other"];
      };
  };
  initialProcess =
    (lib.evalModules {
      inherit lib;
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/configuration.nix
        ../../pkgs/system/_init-system/module.nix
        ../../pkgs/system/_aos-init-provider/module.nix
        {
          aos.activation.scope = ["test" "initrd"];
          aos.abilities.configuration.operations.file.handler.program = pkgs.buildPackages.aos-configuration-provider;
          aos.abilities.initSystem.operations.install.effects = {
            enabled.input.executable = "${pkgs.bash}/bin/bash";
            disabled = {
              enable = false;
              input.executable = "${pkgs.bash}/bin/bash";
            };
          };
        }
      ];
    }).config.aos.activation.graph.nodes;
  composedInputs = builtins.fromJSON (builtins.unsafeDiscardStringContext (inputs initialProcess));
  rendered = import renderer {
    inherit lib;
    inherit (pkgs) runCommand;
    jq = pkgs.buildPackages.jq;
    configurationProvider = pkgs.buildPackages.aos-configuration-provider;
    nodes = fixtures // initialProcess;
  };
in {
  checks = {
    selectsOnlyEtcConfigurationNodes = builtins.length (builtins.fromJSON (inputs fixtures)) == 4;
    selectsEnabledConfigurationChildren =
      builtins.length composedInputs
      == 1
      && (builtins.head composedInputs).input.path == "/etc/aos/init.json"
      && (builtins.head composedInputs).input.value.executable == "${pkgs.bash}/bin/bash";
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
    test ! -e ${rendered}/etc/test/other.conf
    ${pkgs.jq}/bin/jq -e --arg executable '${pkgs.bash}/bin/bash' \
      '.schema == "aos.init-command/v1" and .executable == $executable' \
      ${rendered}/etc/aos/init.json > /dev/null
    # Exercise the same projection the initrd builder uses, after Nix has
    # normalized the renderer's store files to read-only modes.
    test "$(stat -c %a ${rendered}/etc/test/mode.conf)" = 444
    "$CONFIG_SHELL" ${../../pkgs/system/_systemd-abilities/platform/_install-initrd-configuration.sh} \
      ${rendered} "$TMPDIR/image" ${pkgs.jq}/bin/jq
    test "$(stat -c %a "$TMPDIR/image/etc/test/mode.conf")" = 640
    test "$(stat -c %a "$TMPDIR/image/etc/test/plain.conf")" = 444
    cmp ${rendered}/etc/test/data.json "$TMPDIR/image/etc/test/data.json"
    if "$CONFIG_SHELL" ${../../pkgs/system/_systemd-abilities/platform/_install-initrd-configuration.sh} \
      ${rendered} "$TMPDIR/image" ${pkgs.jq}/bin/jq; then
      echo "configuration projection replaced an existing image file" >&2
      exit 1
    fi
    mkdir -p "$TMPDIR/redirected/etc" "$TMPDIR/outside"
    ln -s "$TMPDIR/outside" "$TMPDIR/redirected/etc/test"
    if "$CONFIG_SHELL" ${../../pkgs/system/_systemd-abilities/platform/_install-initrd-configuration.sh} \
      ${rendered} "$TMPDIR/redirected" ${pkgs.jq}/bin/jq; then
      echo "configuration projection traversed a platform symlink" >&2
      exit 1
    fi
    test -z "$(ls -A "$TMPDIR/outside")"
    mkdir -p "$out"
    echo PASS > "$out/result"
  '';
}

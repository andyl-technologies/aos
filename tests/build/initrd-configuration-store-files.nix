##! Verifies bounded immutable fragments through the actual initrd provider.
{
  pkgs,
  lib,
}: let
  source = pkgs.runCommand "initrd-configuration-source-fixture" {} ''
    mkdir -p "$out"
    head -c 400000 /dev/zero | tr '\000' x > "$out/large"
    printf 'immutable\000source\n' > "$out/binary"
  '';
  fragment = path: maximumBytes: {
    storePath = "${source}/${path}";
    inherit maximumBytes;
  };
  node = name: fragments: {
    identity = ["initrd" "configuration" "file" name];
    input = {
      path = "/etc/${name}";
      content = null;
      inherit fragments;
      format = "text";
      value = null;
      owner = null;
      group = null;
      mode = "0400";
    };
  };
  render = nodes:
    import ../../pkgs/system/_systemd-abilities/platform/_initrd-configuration.nix {
      inherit lib nodes;
      inherit (pkgs) runCommand jq;
      configurationProvider = pkgs.aos-configuration-provider;
    };
  rendered = render {
    large = node "large" [(fragment "large" 400000)];
    binary = node "binary" [(fragment "binary" 1024)];
  };
  rejected = fragments: !(builtins.tryEval (render {bad = node "bad" fragments;}).drvPath).success;
  oversized = render {oversized = node "oversized" [(fragment "large" 399999)];};
in
  assert rejected [
    {
      credentialPath = "/run/credentials/secret";
      maximumBytes = 1024;
    }
  ];
  assert rejected [
    {
      storePath = "/run/mutable-source";
      maximumBytes = 1024;
    }
  ];
  assert rejected [
    {
      storePath = "${source}/../mutable-source";
      maximumBytes = 1024;
    }
  ];
    pkgs.runCommand "initrd-configuration-store-files-check" {
      buildDeps = [pkgs.coreutils pkgs.diffutils pkgs.jq];
      # Keep this invocation available for the provider's limit-rejection check.
      oversizedInvocation = oversized.configurationJSON;
      passAsFile = ["oversizedInvocation"];
    } ''
      cmp ${source}/large ${rendered}/etc/large
      cmp ${source}/binary ${rendered}/etc/binary
      ${pkgs.jq}/bin/jq -e \
        '. == {"/etc/large": "0400", "/etc/binary": "0400"}' \
        ${rendered}/modes.json > /dev/null

      ${pkgs.jq}/bin/jq --arg destination "$TMPDIR/oversized" \
        '.[0] | .input.path = $destination' \
        "$oversizedInvocationPath" > oversized.json
      if ${pkgs.aos-configuration-provider}/bin/aos-configuration-provider \
        --state-directory "$TMPDIR/state" apply < oversized.json > result.json 2> error.log; then
        echo 'oversized immutable fragment was accepted' >&2
        exit 1
      fi
      test ! -e "$TMPDIR/oversized"
      mkdir -p "$out"
      echo PASS > "$out/result"
    ''

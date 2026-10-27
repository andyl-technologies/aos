##! Replays the retained SELinux initrd module from its sole admitted NAR.
{
  lib,
  pkgs,
}: let
  policy = pkgs.writeTextFile {
    name = "selinux-initrd-pure-evaluation-policy";
    destination = "/fixture";
    text = "immutable policy producer";
  };
  selected = import ../../modules/security/_selinux-initrd-configuration.nix {
    inherit lib policy;
  };
  provisioner = pkgs.writeTextFile {
    name = "selinux-initrd-pure-evaluation-provisioner";
    destination = "/bin/aos-selinux-runtime-roots";
    text = "immutable provisioner producer";
  };
  protectedRootPreparation = {
    executable = "${provisioner}/bin/aos-selinux-runtime-roots";
    prepareOwners = true;
    varRootContext = "system_u:object_r:aos_sandbox_var_root_t";
  };
  protectedSelection = import ../../modules/security/_selinux-initrd-configuration.nix {
    inherit lib policy protectedRootPreparation;
  };
  measuredSelection = import ../../modules/security/_selinux-initrd-configuration.nix {
    inherit lib policy protectedRootPreparation;
    protectMeasuredVar = true;
  };
  configuration = builtins.head selected.configuration;
  protectedConfiguration = assert protectedSelection.supplementalInputs == ["${policy}" "${provisioner}"];
    builtins.head protectedSelection.configuration;
  measuredConfiguration = builtins.head measuredSelection.configuration;
  absoluteImport = builtins.toFile "selinux-initrd-absolute-import.nix" ''
    { imports = [${../../modules/security/_selinux-initrd-policy.nix}]; }
  '';
in
  pkgs.runCommand "selinux-initrd-pure-evaluation-check" {
    buildDeps = [pkgs.coreutils pkgs.nix pkgs.jq pkgs.grep] ++ protectedSelection.supplementalInputs;
  } ''
    export XDG_CACHE_HOME="$TMPDIR/cache"
    export XDG_STATE_HOME="$TMPDIR/state"
    mkdir -p "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$TMPDIR/admitted"

    # Export only the retained module, as the native evaluator does. The
    # original /nix/store inputs must not become ambient import authority.
    evaluate_module() {
      install -m 0600 "$1" "$TMPDIR/admitted/default.nix"
      module_hash=$(${pkgs.nix}/bin/nix --extra-experimental-features nix-command \
        hash path "$TMPDIR/admitted")
      ${pkgs.nix}/bin/nix-instantiate --store "local?root=$TMPDIR/store" \
        --extra-experimental-features 'nix-command flakes' \
        --eval --strict --json --pure-eval \
        --option restrict-eval true --option substituters "" \
        --option allow-import-from-derivation false \
        --option allowed-uris "path:$TMPDIR/admitted/" \
        --expr "let
          resolve = path: let
            value = import path;
            parents = map resolve (value.imports or []);
          in builtins.deepSeq parents value;
        in resolve (builtins.fetchTree {
          type = \"path\";
          path = \"$TMPDIR/admitted/\";
          narHash = \"$module_hash\";
        }).outPath"
    }

    if evaluate_module ${absoluteImport} > rejected.json 2> rejected.log; then
      echo 'pure evaluation accepted an unadmitted absolute import' >&2
      exit 1
    fi
    if ! ${pkgs.grep}/bin/grep -F 'forbidden in pure evaluation mode' rejected.log; then
      cat rejected.log >&2
      exit 1
    fi

    evaluate_module ${configuration} > module.json
    ${pkgs.jq}/bin/jq -e --arg policy ${lib.escapeShellArg (toString policy)} '
      . as $module
      | $module.aos.abilities.configuration.operations.file.effects as $effects
      | $module.aos.security.selinux == {
        enable: true, bootMode: "immutable-stage0", policy: "aos"
      }
      and $effects["selinux-initrd-config"].input.content
          == "SELINUX=enforcing\nSELINUXTYPE=aos\n"
      and $effects["selinux-initrd-file-contexts"].input.fragments[0].storePath
          == ($policy + "/etc/selinux/aos/contexts/files/file_contexts")
      and $effects["selinux-initrd-file-context-substitutions"].input.fragments[0].storePath
          == ($policy + "/etc/selinux/aos/contexts/files/file_contexts.subs_dist")
      and $effects["selinux-initrd-dbus-contexts"].input.path
          == "/etc/selinux/aos/contexts/dbus_contexts"
      and $effects["selinux-initrd-dbus-contexts"].input.mode == "0444"
      and $effects["selinux-initrd-dbus-contexts"].input.fragments == [{
        storePath: ($policy + "/etc/selinux/aos/contexts/dbus_contexts"),
        maximumBytes: 1048576
      }]
    ' module.json > /dev/null

    # Host-only module selections disappear during native initrd replay. Its
    # admitted data must still retain the exact producer without importing it.
    evaluate_module ${protectedConfiguration} > protected-module.json
    ${pkgs.jq}/bin/jq -e \
      --arg executable ${lib.escapeShellArg protectedRootPreparation.executable} \
      --arg context ${lib.escapeShellArg protectedRootPreparation.varRootContext} '
      .aos.boot.substrateServices.protectedRootPreparation == {
        executable: $executable,
        prepareOwners: true,
        varRootContext: $context
      }
      and .aos.storageProvisioning.protectedVarContext == $context
      and (.aos.security | has("measuredVar") | not)
    ' protected-module.json > /dev/null

    evaluate_module ${measuredConfiguration} > measured-module.json
    ${pkgs.jq}/bin/jq -e \
      --slurpfile plain protected-module.json \
      --arg context ${lib.escapeShellArg protectedRootPreparation.varRootContext} '
      .aos.boot == $plain[0].aos.boot
      and .aos.storageProvisioning == $plain[0].aos.storageProvisioning
      and .aos.security.selinux == $plain[0].aos.security.selinux
      and .aos.security.measuredVar.protectedVarContext == $context
    ' measured-module.json > /dev/null
    ${pkgs.jq}/bin/jq -e '
      (.aos.boot.substrateServices // {} | has("protectedRootPreparation")) | not
    ' module.json > /dev/null

    mkdir -p "$out"
    cp module.json protected-module.json measured-module.json "$out/"
    echo PASS > "$out/result"
  ''

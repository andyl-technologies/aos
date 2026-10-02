##! Keeps projection source identity while excluding unselected payload outputs.
{
  lib,
  pkgs,
}: let
  schema = pkgs.mkDerivation {
    pname = "native-projection-schema";
    version = "1";
    src = null;
    module = ../../pkgs/tools/_aos-metadata-provider/facts;
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  dependency = pkgs.mkDerivation {
    pname = "native-projection-available-dependency";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  package = pkgs.mkDerivation {
    pname = "native-projection-payload";
    version = "1";
    src = null;
    module = ../effects/package-interface;
    moduleDeps = [schema];
    runtimeDeps = [dependency pkgs.binutils];
    outputs = ["out" "unused"];
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out" "$unused"'';
      }
    ];
  };
  custodySource = builtins.toFile "native-projection-custody.nix" ''
    throw "Retained source custody must not execute configuration."
  '';
  descriptor = retainPayloads:
    lib.build.evaluationInput {
      inherit lib pkgs retainPayloads;
      packages = [package];
      supplementalInputs = [custodySource];
      scope = ["projection-check"];
      system = pkgs.stdenv.hostPlatform.system;
    };
  full = descriptor true;
  projection = descriptor false;
  inventory = root: (lib.build.closureInfo {inherit pkgs;}) {rootPaths = [root];};
  fullInventory = inventory full;
  projectionInventory = inventory projection;
  capsule = import ../../pkgs/boot/_aos-host-evaluation-input/build.nix {
    inherit pkgs;
    evaluationInput = projection;
  };
  capsuleInventory = inventory capsule;
  bundle = selected: consumeAvailable: let
    evaluated = lib.evalPackageModules {
      packages = [selected];
      scope = ["projection-bundle"];
      modules = lib.optional consumeAvailable {
        aos.abilities.echo.operations.run = {
          handler.program = selected;
          effects.retained.input.message = "${package.unused}/marker:${dependency}/marker:${pkgs.binutils}/marker";
        };
      };
    };
  in
    import ../../pkgs/containers/_aos-oci-backend/deployment-bundle.nix {
      inherit lib pkgs;
      packages = [selected];
      inherit (evaluated.deployment) graph scope;
      system = pkgs.stdenv.hostPlatform.system;
    };
  primaryBundle = bundle package false;
  alternateBundle = bundle package.unused false;
  consumedBundle = bundle package true;
  primaryBundleInventory = inventory primaryBundle;
  alternateBundleInventory = inventory alternateBundle;
  consumedBundleInventory = inventory consumedBundle;
  artifactText = lib.build.writeArtifact {
    inherit (pkgs.buildPackages or pkgs) bash coreutils;
    system = pkgs.stdenv.buildPlatform.system;
  };
  # Real toolchain siblings reproduce the scanner leak from a compiler-backed
  # text builder. Catalog locators remain inert; selected paths retain custody.
  companion = retainStatic:
    artifactText {
      name = "native-projection-toolchain-catalog-${
        if retainStatic
        then "selected"
        else "metadata"
      }";
      destination = "/catalog.json";
      text = builtins.toJSON {
        available = builtins.unsafeDiscardStringContext (toString pkgs.glibc.dev);
        selected =
          if retainStatic
          then toString pkgs.glibc.static
          else builtins.unsafeDiscardStringContext (toString pkgs.glibc.static);
        source = toString custodySource;
      };
    };
  metadataCompanion = companion false;
  selectedCompanion = companion true;
  metadataCompanionInventory = inventory metadataCompanion;
  selectedCompanionInventory = inventory selectedCompanion;
  glibcToolsEnvelopeInventory = inventory pkgs.glibc-tools.deploymentArtifact;
in
  pkgs.mkDerivation {
    pname = "native-projection-input-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.jq fullInventory projectionInventory capsuleInventory primaryBundleInventory alternateBundleInventory consumedBundleInventory metadataCompanionInventory selectedCompanionInventory glibcToolsEnvelopeInventory];
    phases = [
      {
        name = "check";
        script = ''
          ${pkgs.jq}/bin/jq -en --slurpfile full ${full} --slurpfile projection ${projection} \
            '$full == $projection and ($projection[0].moduleEnvelopes | keys) == ["native-projection-payload", "native-projection-schema"]' >/dev/null
          ${pkgs.jq}/bin/jq -e --arg payload ${lib.escapeShellArg (toString package)} \
            --arg unused ${lib.escapeShellArg (toString package.unused)} \
            'any(.paths[]; .path == $payload) and (all(.paths[]; .path != $unused))' \
            ${fullInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg payload ${lib.escapeShellArg (toString package)} \
            --arg unused ${lib.escapeShellArg (toString package.unused)} \
            --arg source ${lib.escapeShellArg (toString package.module)} \
            --arg schemaPayload ${lib.escapeShellArg (toString schema)} \
            --arg schemaSource ${lib.escapeShellArg (toString schema.module)} \
            --arg envelope ${lib.escapeShellArg (toString package.deploymentArtifact)} \
            --arg schemaEnvelope ${lib.escapeShellArg (toString schema.deploymentArtifact)} \
            --arg custody ${lib.escapeShellArg (toString custodySource)} \
            'all(.paths[]; .path != $payload and .path != $unused and .path != $schemaPayload)
              and any(.paths[]; .path == $source)
              and any(.paths[]; .path == $schemaSource)
              and any(.paths[]; .path == $envelope)
              and any(.paths[]; .path == $schemaEnvelope)
              and any(.paths[]; .path == $custody)' \
            ${projectionInventory}/inventory.json >/dev/null
          # The complete catalogs remain readable while only chosen outputs
          # and dependencies used by the graph enter each actual store closure.
          ${pkgs.jq}/bin/jq -e --arg primary ${lib.escapeShellArg (toString package)} \
            --arg alternate ${lib.escapeShellArg (toString package.unused)} \
            --arg dependency ${lib.escapeShellArg (toString dependency)} \
            'any(.paths[]; .path == $primary)
              and all(.paths[]; .path != $alternate and .path != $dependency)' \
            ${primaryBundleInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg primary ${lib.escapeShellArg (toString package)} \
            --arg alternate ${lib.escapeShellArg (toString package.unused)} \
            --arg dependency ${lib.escapeShellArg (toString dependency)} \
            'any(.paths[]; .path == $alternate)
              and all(.paths[]; .path != $primary and .path != $dependency)' \
            ${alternateBundleInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg primary ${lib.escapeShellArg (toString package)} \
            --arg alternate ${lib.escapeShellArg (toString package.unused)} \
            --arg dependency ${lib.escapeShellArg (toString dependency)} \
            'any(.paths[]; .path == $primary)
              and any(.paths[]; .path == $alternate)
              and any(.paths[]; .path == $dependency)' \
            ${consumedBundleInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg alternate ${lib.escapeShellArg (toString package.unused)} \
            --arg dependency ${lib.escapeShellArg (toString dependency)} \
            '.artifacts[0].outputs.unused == $alternate
              and any(.packages[]; .artifacts.dependencies."native-projection-available-dependency".path == $dependency)' \
            ${primaryBundle}/transaction.json >/dev/null
          # Compiler-backed JSON writers used to retain this real build tool
          # merely because its inert catalog path was scanner-visible.
          for inventory in \
            ${fullInventory}/inventory.json \
            ${projectionInventory}/inventory.json \
            ${primaryBundleInventory}/inventory.json \
            ${alternateBundleInventory}/inventory.json \
            ${capsuleInventory}/inventory.json; do
            ${pkgs.jq}/bin/jq -e --arg tool ${lib.escapeShellArg (toString pkgs.binutils)} \
              'all(.paths[]; .path != $tool)' "$inventory" >/dev/null
          done
          ${pkgs.jq}/bin/jq -e --arg tool ${lib.escapeShellArg (toString pkgs.binutils)} \
            'any(.paths[]; .path == $tool)' \
            ${consumedBundleInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg tool ${lib.escapeShellArg (toString pkgs.binutils)} \
            'any(.packages[]; .artifacts.dependencies.binutils.path == $tool)' \
            ${primaryBundle}/transaction.json >/dev/null
          test -L ${capsule}/evaluation.json
          cmp ${capsule}/evaluation.json ${projection}
          ${pkgs.jq}/bin/jq -e --arg dev ${lib.escapeShellArg (toString pkgs.glibc.dev)} \
            --arg static ${lib.escapeShellArg (toString pkgs.glibc.static)} \
            --arg source ${lib.escapeShellArg (toString custodySource)} \
            'all(.paths[]; .path != $dev and .path != $static)
              and any(.paths[]; .path == $source)' \
            ${metadataCompanionInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg dev ${lib.escapeShellArg (toString pkgs.glibc.dev)} \
            --arg static ${lib.escapeShellArg (toString pkgs.glibc.static)} \
            --arg source ${lib.escapeShellArg (toString custodySource)} \
            'all(.paths[]; .path != $dev)
              and any(.paths[]; .path == $static)
              and any(.paths[]; .path == $source)' \
            ${selectedCompanionInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg dev ${lib.escapeShellArg (toString pkgs.glibc.dev)} \
            --arg static ${lib.escapeShellArg (toString pkgs.glibc.static)} \
            'all(.paths[]; .path != $dev and .path != $static)' \
            ${glibcToolsEnvelopeInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg dev ${lib.escapeShellArg (toString pkgs.glibc.dev)} \
            --arg static ${lib.escapeShellArg (toString pkgs.glibc.static)} \
            '.available == $dev and .selected == $static' \
            ${metadataCompanion}/catalog.json >/dev/null
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }

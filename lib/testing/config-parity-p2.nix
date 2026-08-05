# RFC-0011 P2 stock/native manifest and option-graph parity gate.
{
  pkgs,
  lib,
}: let
  aos = import ../../. {};
  system = aos.mkSystem {
    modules = [../../systems/server.nix];
  };
  baseLib = system.config.aos.config.evalAtBoot.baseLib;

  fixtureRoot = ./fixtures/config-parity-p2;
  hostModule = fixtureRoot + "/host.nix";
  firewallRoot = builtins.path {
    path = fixtureRoot + "/firewall";
    name = "rfc0011-parity-firewall-config";
  };
  webRoot = builtins.path {
    path = fixtureRoot + "/web";
    name = "rfc0011-parity-web-config";
  };
  databaseRoot = builtins.path {
    path = fixtureRoot + "/database";
    name = "rfc0011-parity-database-config";
  };
  telemetryRoot = builtins.path {
    path = fixtureRoot + "/telemetry";
    name = "rfc0011-parity-telemetry-config";
  };

  # This is the P1 publish-time interface projection. The stock side maps
  # declared reads/writes to the canonical graph; the native side receives
  # none of it and must observe the same accesses while executing the modules.
  interfaces = [
    {
      package = "firewall";
      reads = [];
      writes = ["firewall.port"];
    }
    {
      package = "web";
      reads = ["firewall.port"];
      writes = ["web.port"];
    }
    {
      package = "database";
      reads = [];
      writes = ["database.port"];
    }
    {
      package = "telemetry";
      reads = [
        "firewall.port"
        "web.port"
        "database.port"
      ];
      writes = ["telemetry.summary"];
    }
  ];
  rootOwners = {
    database = "database";
    firewall = "firewall";
    telemetry = "telemetry";
    web = "web";
  };
  readAccesses = lib.concatMap
    (interface:
      builtins.map
      (option: let
        root = builtins.head (lib.splitString "." option);
        provider = rootOwners.${root} or null;
      in
        {
          inherit (interface) package;
          inherit option;
          kind = "read";
        }
        // lib.optionalAttrs (provider != null && provider != interface.package) {
          inherit provider;
        })
      interface.reads)
    interfaces;
  writeAccesses = lib.concatMap
    (interface:
      builtins.map
      (option: {
        inherit (interface) package;
        inherit option;
        kind = "write";
      })
      interface.writes)
    interfaces;
  accessLess = left: right:
    if left.package != right.package
    then left.package < right.package
    else if left.option != right.option
    then left.option < right.option
    else if left.kind != right.kind
    then left.kind == "read"
    else (left.provider or "") < (right.provider or "");
  expectedGraph.accesses = builtins.sort accessLess (readAccesses ++ writeAccesses);
  expectedGraphJson = builtins.toFile
    "rfc0011-config-parity-p2-graph.json"
    (builtins.toJSON expectedGraph);

  entryRoot = pkgs.writeTextFile {
    name = "rfc0011-config-parity-p2-entry";
    destination = "/entry.nix";
    text = ''
      let
      baseLib = import ${baseLib};
      hostModule = import ${hostModule};
      system = baseLib.evalHostConfig {
        operatorModules = [ hostModule ];
        packageModules = [
          {
            name = "firewall";
            authorization = { owns = []; contributes = {}; };
            configRoot = ${firewallRoot};
            module = ${firewallRoot}/module.nix;
            outputs = { self = "${baseLib}"; dependencies = {}; };
          }
          {
            name = "web";
            authorization = {
              owns = [];
              contributes.firewall = [];
            };
            configRoot = ${webRoot};
            module = ${webRoot}/module.nix;
            outputs = { self = "${baseLib}"; dependencies = {}; };
          }
          {
            name = "database";
            authorization = { owns = []; contributes = {}; };
            configRoot = ${databaseRoot};
            module = ${databaseRoot}/module.nix;
            outputs = { self = "${baseLib}"; dependencies = {}; };
          }
          {
            name = "telemetry";
            authorization = {
              owns = [];
              contributes = {
                database = [];
                firewall = [];
                web = [];
              };
            };
            configRoot = ${telemetryRoot};
            module = ${telemetryRoot}/module.nix;
            outputs = { self = "${baseLib}"; dependencies = {}; };
          }
        ];
        structuredErrors = true;
      };
    in {
      optionWrites = system._optionWrites;
      manifest = system.config.system.build.configManifest // {
        config = baseLib.lib.recursiveUpdate
          system.config.system.build.configManifest.config
          system.config.aos.apm.installAtBoot.config;
        credentials = baseLib.lib.recursiveUpdate
          system.config.system.build.configManifest.credentials
          (baseLib.lib.recursiveUpdate
            system.config.aos.apm.installAtBoot.credentials
            (builtins.mapAttrs
              (_package: handles: builtins.mapAttrs
                (name: systemCredential: {
                  inherit name;
                  source = null;
                  encrypted = true;
                  units = [];
                  ref = "system-credential:''${systemCredential}";
                })
                handles)
              system.config.aos.apm.installAtBoot.systemCredentials));
      };
      }
    '';
  };
  entry = entryRoot + "/entry.nix";
  stockEntryRoot = pkgs.writeTextFile {
    name = "rfc0011-config-parity-p2-stock";
    destination = "/entry.nix";
    text = ''
      let evaluated = import ${entry};
      in {
        graph = builtins.fromJSON (builtins.readFile ${expectedGraphJson});
        manifest = evaluated.manifest;
      }
    '';
  };
  stockEntry = stockEntryRoot + "/entry.nix";
  cacheLeaf = fixtureRoot + "/cache-leaf.nix";
  cacheHostV1 = builtins.toFile "rfc0011-config-parity-p2-cache-host-v1.nix" ''
    { label = "before"; offset = 1; }
  '';
  cacheHostV2 = builtins.toFile "rfc0011-config-parity-p2-cache-host-v2.nix" ''
    { label = "after"; offset = 2; }
  '';
  cacheEntryTemplate = builtins.toFile "rfc0011-config-parity-p2-cache-entry.nix" ''
    let host = import ./host.nix;
    in {
      manifest = {
        inherit (host) label;
        total = (import ${cacheLeaf}) + host.offset;
      };
      optionWrites = [];
    }
  '';
  unchangedCacheEntry = builtins.toFile "rfc0011-config-parity-p2-cache-unchanged.nix" ''
    {
      manifest.total = import ${cacheLeaf};
      optionWrites = [];
    }
  '';
  resourceDivergentEntry = builtins.toFile "rfc0011-config-parity-p2-resource-divergent.nix" ''
    let loop = value: loop (value + 1);
    in {
      manifest.value = loop 0;
      optionWrites = [];
    }
  '';
  staticDivergentEntry = builtins.toFile "rfc0011-config-parity-p2-static-divergent.nix" ''
    let bottom = bottom;
    in {
      manifest.value = bottom;
      optionWrites = [];
    }
  '';
  collectionsEntry = fixtureRoot + "/corpus/collections.nix";
  attrsetsEntry = fixtureRoot + "/corpus/attrsets.nix";
in
  pkgs.mkDerivation {
    pname = "config-parity-p2-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.aos-nix pkgs.nix pkgs.jq pkgs.diffutils pkgs.grep];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          mkdir -p "$out" "$TMPDIR/cache" "$TMPDIR/cache-case"

          # The derivation sandbox is the stock evaluator's filesystem and
          # network boundary. Nix pure-eval cannot authorize store paths
          # embedded by a generated expression without admitting /nix/store.
          ${pkgs.nix}/bin/nix-instantiate \
            --store dummy:// --eval --strict --json \
            --option allow-import-from-derivation false \
            -I ${stockEntry} -I ${entry} -I ${expectedGraphJson} \
            -I ${baseLib} -I ${hostModule} \
            -I ${firewallRoot} -I ${webRoot} \
            -I ${databaseRoot} -I ${telemetryRoot} \
            ${stockEntry} > "$TMPDIR/stock.json"

          ${pkgs.aos-nix}/bin/aos-nix-eval ${entry} \
            --allow ${baseLib} \
            --allow ${hostModule} \
            --allow ${firewallRoot} \
            --allow ${webRoot} \
            --allow ${databaseRoot} \
            --allow ${telemetryRoot} \
            --module-owner ${firewallRoot}=firewall \
            --module-owner ${webRoot}=web \
            --module-owner ${databaseRoot}=database \
            --module-owner ${telemetryRoot}=telemetry \
            --root-owner database=database \
            --root-owner firewall=firewall \
            --root-owner telemetry=telemetry \
            --root-owner web=web \
            > "$TMPDIR/native.json"

          ${pkgs.jq}/bin/jq -S '{manifest, graph}' \
            "$TMPDIR/native.json" > "$TMPDIR/native-canonical.json"
          ${pkgs.jq}/bin/jq -S . \
            "$TMPDIR/stock.json" > "$TMPDIR/stock-canonical.json"
          ${pkgs.diffutils}/bin/cmp \
            "$TMPDIR/stock-canonical.json" "$TMPDIR/native-canonical.json"
          ${pkgs.jq}/bin/jq -e '
            .manifest.schema == "aos.config-manifest/v1"
            and .manifest.etc."rfc0011/parity".text == "providers=8080:8080:5432\n"
            and (.graph.accesses | length == 8)
            and any(.graph.accesses[];
              .package == "web"
              and .option == "firewall.port"
              and .kind == "read"
              and .provider == "firewall")
            and ([.graph.accesses[] | select(.kind == "read" and .provider != null) | .provider] | unique)
              == ["database", "firewall", "web"]
            and .stats.evaluationIterations == 1
            and .stats.providerFixpointIterations == 0
            and (.stats.importsEvaluated >= 5)
          ' "$TMPDIR/native.json" >/dev/null

          # Option-read observations are semantic output, not an evaluator
          # side effect that may disappear behind a force-cache hit. Exercise
          # the materializing and warm runs with the imported helper/alias/
          # getAttr fixture and require byte-identical canonical graphs.
          for pass in cache-cold materialized warm; do
            ${pkgs.aos-nix}/bin/aos-nix-eval ${entry} \
              --allow ${baseLib} \
              --allow ${hostModule} \
              --allow ${firewallRoot} \
              --allow ${webRoot} \
              --allow ${databaseRoot} \
              --allow ${telemetryRoot} \
              --module-owner ${firewallRoot}=firewall \
              --module-owner ${webRoot}=web \
              --module-owner ${databaseRoot}=database \
              --module-owner ${telemetryRoot}=telemetry \
              --root-owner database=database \
              --root-owner firewall=firewall \
              --root-owner telemetry=telemetry \
              --root-owner web=web \
              --cache-root "$TMPDIR/graph-cache" \
              > "$TMPDIR/native-$pass.json"
          done
          ${pkgs.jq}/bin/jq -S .graph "$TMPDIR/native.json" > "$TMPDIR/graph-cold.json"
          ${pkgs.jq}/bin/jq -S .graph "$TMPDIR/native-cache-cold.json" > "$TMPDIR/graph-cache-cold.json"
          ${pkgs.jq}/bin/jq -S .graph "$TMPDIR/native-materialized.json" > "$TMPDIR/graph-materialized.json"
          ${pkgs.jq}/bin/jq -S .graph "$TMPDIR/native-warm.json" > "$TMPDIR/graph-warm.json"
          ${pkgs.diffutils}/bin/cmp "$TMPDIR/graph-cold.json" "$TMPDIR/graph-cache-cold.json"
          ${pkgs.diffutils}/bin/cmp "$TMPDIR/graph-cold.json" "$TMPDIR/graph-materialized.json"
          ${pkgs.diffutils}/bin/cmp "$TMPDIR/graph-cold.json" "$TMPDIR/graph-warm.json"

          # The checked-in corpus covers the module system plus independent
          # collection and attrset semantics. Every case is compared without
          # an expected-difference allowlist.
          ${pkgs.nix}/bin/nix-instantiate \
            --store dummy:// --eval --strict --json \
            --option allow-import-from-derivation false \
            -I ${collectionsEntry} ${collectionsEntry} \
            > "$TMPDIR/collections-stock.json"
          ${pkgs.aos-nix}/bin/aos-nix-eval ${collectionsEntry} \
            > "$TMPDIR/collections-native.json"
          ${pkgs.jq}/bin/jq -S '.manifest' \
            "$TMPDIR/collections-stock.json" > "$TMPDIR/collections-stock-canonical.json"
          ${pkgs.jq}/bin/jq -S '.manifest' \
            "$TMPDIR/collections-native.json" > "$TMPDIR/collections-native-canonical.json"
          ${pkgs.diffutils}/bin/cmp \
            "$TMPDIR/collections-stock-canonical.json" \
            "$TMPDIR/collections-native-canonical.json"

          ${pkgs.nix}/bin/nix-instantiate \
            --store dummy:// --eval --strict --json \
            --option allow-import-from-derivation false \
            -I ${attrsetsEntry} ${attrsetsEntry} \
            > "$TMPDIR/attrsets-stock.json"
          ${pkgs.aos-nix}/bin/aos-nix-eval ${attrsetsEntry} \
            > "$TMPDIR/attrsets-native.json"
          ${pkgs.jq}/bin/jq -S '.manifest' \
            "$TMPDIR/attrsets-stock.json" > "$TMPDIR/attrsets-stock-canonical.json"
          ${pkgs.jq}/bin/jq -S '.manifest' \
            "$TMPDIR/attrsets-native.json" > "$TMPDIR/attrsets-native-canonical.json"
          ${pkgs.diffutils}/bin/cmp \
            "$TMPDIR/attrsets-stock-canonical.json" \
            "$TMPDIR/attrsets-native-canonical.json"

          # Establish a persistent cache, then edit only the host leaf. The
          # incrementally recomputed result must equal a fresh cold evaluation
          # of the edited input, and deterministic forced work must be <=20%.
          cp ${cacheEntryTemplate} "$TMPDIR/cache-case/entry.nix"
          cp ${cacheHostV1} "$TMPDIR/cache-case/host.nix"
          chmod u+w "$TMPDIR/cache-case/host.nix"
          ${pkgs.aos-nix}/bin/aos-nix-eval "$TMPDIR/cache-case/entry.nix" \
            --allow ${cacheLeaf} --allow "$TMPDIR/cache-case" \
            --cache-root "$TMPDIR/cache" \
            > "$TMPDIR/cache-v1-cold.json"
          cp ${cacheHostV2} "$TMPDIR/cache-case/host.nix"
          ${pkgs.aos-nix}/bin/aos-nix-eval "$TMPDIR/cache-case/entry.nix" \
            --allow ${cacheLeaf} --allow "$TMPDIR/cache-case" \
            --cache-root "$TMPDIR/cache" \
            > "$TMPDIR/cache-v2-warm.json"
          ${pkgs.aos-nix}/bin/aos-nix-eval "$TMPDIR/cache-case/entry.nix" \
            --allow ${cacheLeaf} --allow "$TMPDIR/cache-case" \
            --cache-root "$TMPDIR/cache-cold-v2" \
            > "$TMPDIR/cache-v2-cold.json"
          ${pkgs.jq}/bin/jq -S '.manifest' "$TMPDIR/cache-v2-warm.json" \
            > "$TMPDIR/cache-v2-warm-manifest.json"
          ${pkgs.jq}/bin/jq -S '.manifest' "$TMPDIR/cache-v2-cold.json" \
            > "$TMPDIR/cache-v2-cold-manifest.json"
          ${pkgs.diffutils}/bin/cmp \
            "$TMPDIR/cache-v2-warm-manifest.json" "$TMPDIR/cache-v2-cold-manifest.json"
          warm_forced="$(${pkgs.jq}/bin/jq -r '.stats.thunksForced' "$TMPDIR/cache-v2-warm.json")"
          cold_forced="$(${pkgs.jq}/bin/jq -r '.stats.thunksForced' "$TMPDIR/cache-v2-cold.json")"
          if [ "$((warm_forced * 5))" -gt "$cold_forced" ]; then
            echo "edited-host incremental recomputation exceeded 20%: warm=$warm_forced cold=$cold_forced" >&2
            exit 1
          fi
          ${pkgs.jq}/bin/jq -e \
            '.manifest.label == "after" and .stats.forceCacheHits > 0 and .stats.earlyCutoffs > 0' \
            "$TMPDIR/cache-v2-warm.json" >/dev/null

          # Retain the same-input cache assertion as an independent signal that
          # persistent materialization is active, not merely in-process memoing.
          ${pkgs.aos-nix}/bin/aos-nix-eval ${unchangedCacheEntry} \
            --allow ${cacheLeaf} --cache-root "$TMPDIR/cache" \
            > "$TMPDIR/cache-cold.json"
          ${pkgs.aos-nix}/bin/aos-nix-eval ${unchangedCacheEntry} \
            --allow ${cacheLeaf} --cache-root "$TMPDIR/cache" \
            > "$TMPDIR/cache-materialized.json"
          ${pkgs.aos-nix}/bin/aos-nix-eval ${unchangedCacheEntry} \
            --allow ${cacheLeaf} --cache-root "$TMPDIR/cache" \
            > "$TMPDIR/cache-warm.json"
          ${pkgs.jq}/bin/jq -S '.manifest' "$TMPDIR/cache-cold.json" \
            > "$TMPDIR/cache-cold-manifest.json"
          ${pkgs.jq}/bin/jq -S '.manifest' "$TMPDIR/cache-warm.json" \
            > "$TMPDIR/cache-warm-manifest.json"
          ${pkgs.diffutils}/bin/cmp \
            "$TMPDIR/cache-cold-manifest.json" "$TMPDIR/cache-warm-manifest.json"
          cold_forced="$(${pkgs.jq}/bin/jq -r '.stats.thunksForced' "$TMPDIR/cache-cold.json")"
          ${pkgs.jq}/bin/jq -e --argjson cold "$cold_forced" '
            .stats.forceCacheHits > 0
            and .stats.earlyCutoffs > 0
            and .stats.thunksForced < $cold
          ' "$TMPDIR/cache-warm.json" >/dev/null

          if ${pkgs.aos-nix}/bin/aos-nix-eval ${staticDivergentEntry} \
            --reject-obvious-divergence yes \
            > "$TMPDIR/static-divergent.json" 2> "$TMPDIR/static-divergent.err"; then
            echo "statically divergent native evaluation unexpectedly ran" >&2
            exit 1
          fi
          ${pkgs.grep}/bin/grep -q \
            "static divergence" "$TMPDIR/static-divergent.err"
          if ${pkgs.grep}/bin/grep -q \
            "resource limit exceeded" "$TMPDIR/static-divergent.err"; then
            echo "static divergence reached the runtime resource backstop" >&2
            exit 1
          fi

          if ${pkgs.aos-nix}/bin/aos-nix-eval ${resourceDivergentEntry} \
            --max-eval-steps 100 \
            > "$TMPDIR/divergent.json" 2> "$TMPDIR/divergent.err"; then
            echo "divergent native evaluation unexpectedly succeeded" >&2
            exit 1
          fi
          ${pkgs.grep}/bin/grep -q \
            "resource limit exceeded" "$TMPDIR/divergent.err"

          echo "stock/native full-manifest parity: OK" > "$out/result"
          echo "three-case stock/native fixture corpus parity: OK" >> "$out/result"
          echo "one native eval discovers all providers with no fixpoint rounds: OK" >> "$out/result"
          echo "edited-host incremental/cold identity and <=20% recomputation: OK" >> "$out/result"
          echo "static obvious-divergence rejection: OK" >> "$out/result"
          echo "structured in-engine resource limit: OK" >> "$out/result"
        '';
      }
    ];
  }

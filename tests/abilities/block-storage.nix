##! Native storage contracts preserve conditional preparation and durable commit ordering.
{
  lib,
  pkgs,
}: let
  fixture = import ./_native-storage-evaluation.nix {inherit lib;};
  context = builtins.toFile "evaluation-input.json" "{}";
  anchor = builtins.toFile "operator.pub" "fixture-public-anchor";
  evaluateWithContext = selectedContext:
    fixture.evaluate {
      packages = [fixture.provisioning];
      evaluationInput = context;
      evaluationInputs = [context anchor] ++ lib.optional (selectedContext != null) selectedContext;
      modules = [
        {
          options.aos.boot.stage = lib.mkOption {
            type = lib.types.enum ["host" "initrd"];
            default = "initrd";
          };
          options.aos.boot.storage.resolvedDevices = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {rootA = "/dev/disk/by-partlabel/root-a";};
          };
          options.aos.boot.secureBoot.measuredBoot.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          config.aos.storageProvisioning = {
            enable = true;
            evaluationContext = selectedContext;
            authorizationConfiguration = {
              schema = "aos.metadata.provisioning-authorization-configuration/v1";
              trust_mode = "signed";
              trusted_config_keys = [
                {
                  kind = "immutable-file";
                  path = anchor;
                  content_sha256 = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "0") 64)}";
                }
              ];
            };
          };
        }
      ];
    };
  evaluated = evaluateWithContext null;
  hostContext = builtins.toFile "host-evaluation-input.json" "{}";
  hostEvaluation = evaluateWithContext hostContext;
  hostNodes = builtins.attrValues hostEvaluation.deployment.graph.nodes;
  hostAuthorize = builtins.head (builtins.filter (node: builtins.elem "authorize" node.identity) hostNodes);
  graph = evaluated.deployment.graph;
  nodes = builtins.attrValues graph.nodes;
  byName = name: builtins.head (builtins.filter (node: builtins.elem name node.identity) nodes);
  prepare = byName "system";
  detect = byName "detect";
  connectivity = byName "ready";
  acquire = byName "acquire";
  bootstrap = byName "bootstrap";
  authorize = byName "authorize";
  authorizedInput = builtins.head (builtins.filter (node: (node.input.name or "") == "authorized-provisioning-input") nodes);
  marker = byName "provisioningMarker";
  evaluate = byName "evaluate";
  planReceipt = builtins.head (builtins.filter (node: (node.input.name or "") == "authorized-provisioning-plan") nodes);
  commit = builtins.head (builtins.filter (node: builtins.elem "storageProvisioning" node.identity && builtins.elem "commit" node.identity) nodes);
  includes = node: producer: builtins.elem (fixture.identity producer) node.dependencies;
  disabled = fixture.evaluate {
    packages = [fixture.crypto];
    modules = [{aos.filesystems.encryptedSwap.enable = false;}];
  };
  invalid = builtins.tryEval (builtins.deepSeq
    (fixture.evaluate {
      packages = [fixture.crypto];
      modules = [{aos.abilities.encryptedMapping.operations.open.effects.cryptswap.input.source = lib.mkForce 7;}];
    }).deployment.graph
    true);
in
  assert builtins.length prepare.handler.children == 10;
  assert prepare.handler.kind == "composition";
  assert prepare.lifetime == "instance";
  assert builtins.all (key: builtins.elem graph.nodes.${key}.lifetime ["instance" "persistent"]) prepare.handler.children;
  assert prepare.handler.exports.authorized_input.identity == authorizedInput.identity;
  assert prepare.handler.exports.authorized_input.output == "path";
  assert prepare.handler.exports.authorized_input_sha256.identity == authorizedInput.identity;
  assert prepare.handler.exports.authorized_input_sha256.output == "content_sha256";
  assert includes connectivity detect;
  assert connectivity.input.required.identity == detect.identity;
  assert connectivity.input.required.output == "need_network";
  assert includes acquire detect && includes acquire connectivity;
  assert includes bootstrap acquire;
  assert includes authorize acquire && includes authorize bootstrap;
  assert authorize.input.configuration.trust_mode == "signed";
  assert authorize.input.evaluation_context == context;
  assert hostAuthorize.input.evaluation_context == hostContext;
  assert builtins.all (entry: entry.assertion) hostEvaluation.config.assertions;
  assert includes authorizedInput authorize;
  assert authorizedInput.lifetime == "persistent";
  assert includes evaluate authorizedInput && includes evaluate marker;
  assert evaluate.handler.executable == "${fixture.aos.packageRuntime}/bin/aos-provisioning-configuration-evaluator";
  assert includes planReceipt evaluate;
  assert planReceipt.lifetime == "persistent";
  assert planReceipt.input.media_type == "application/vnd.aos.provisioning-plan+json";
  assert planReceipt.input.content.identity == evaluate.identity;
  assert planReceipt.input.content.output == "canonical_plan";
  assert prepare.handler.exports.committed_plan.identity == planReceipt.identity;
  assert prepare.handler.exports.committed_plan.output == "path";
  assert includes commit evaluate && includes commit planReceipt;
  assert commit.lifetime == "persistent";
  assert commit.input.request.policy.initialize == "if-unprovisioned";
  assert commit.input.request.policy.committed_divergence == "require-factory-reset";
  assert commit.input.tools.systemd_repart == "${fixture.manager}/bin/systemd-repart";
  assert graph.order != [];
  assert disabled.deployment.graph.nodes == {};
  assert !invalid.success;
  assert builtins.all (entry: entry.assertion) evaluated.config.assertions; true

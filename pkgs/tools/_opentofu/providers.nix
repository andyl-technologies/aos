##! Pins the common providers published in the default OpenTofu mirror.
#
# Each provider is the upstream HashiCorp source that the OpenTofu registry
# publishes under registry.opentofu.org/hashicorp/<type>.
{
  mkProvider,
  jq,
}: let
  # Upgrade tests install an earlier provider release from the public
  # registry before switching to the source-built one.
  registryUpgrade = file: test: {
    inherit file test;
    reason = "installs an earlier release from the provider registry";
  };
in {
  null = mkProvider {
    type = "null";
    version = "3.3.2";
    repository = "hashicorp/terraform-provider-null";
    hash = "sha256-MBUoP1odjf+EDCbIQiAQU639tiZG6NVvqSUlcfu1VNs=";
    modulesHash = "sha256-w/dvZgQuPGaY4Firs3XRs6YbYcoLFk4k2MjLT1Uxw7I=";
    description = "OpenTofu provider for resources that intentionally do nothing";
  };

  random = mkProvider {
    type = "random";
    version = "3.9.1";
    repository = "hashicorp/terraform-provider-random";
    hash = "sha256-CA4qqN2V/57KwYoRysmBATtudV6QwyTXfRxG3Q8PP7c=";
    modulesHash = "sha256-UUsyznc9of4tVIDur2AZ/BW7xmOYWvLLcfSQ4jmiTi4=";
    description = "OpenTofu provider for random values stored in state";
    skippedTests = [
      (registryUpgrade "internal/provider/resource_string_test.go" "TestAccResourceString_StateUpgradeV1toV2")
    ];
  };

  local = mkProvider {
    type = "local";
    version = "2.9.1";
    repository = "hashicorp/terraform-provider-local";
    hash = "sha256-K2ugUyr3R0fuX97WOjHM2xEcfBLoPGQCMkxrFusqhnM=";
    modulesHash = "sha256-MyuMkHIWonaYmBNW81ZeKqYlxXQCzQauQRIJsQiuA1o=";
    description = "OpenTofu provider for local files and commands";
    # The local_command tests run jq and yq as example commands. AOS does
    # not package yq, so only its YAML cases are skipped.
    checkInputs = [jq];
    skippedTests =
      map (test: {
        file = "internal/provider/data_source_local_command_test.go";
        inherit test;
        reason = "runs yq, which is not packaged";
      }) ["TestLocalCommandDataSource_stdout_yaml"]
      ++ map (test: {
        file = "internal/provider/ephemeral_local_command_test.go";
        inherit test;
        reason = "runs yq, which is not packaged";
      }) ["TestLocalCommandEphemeral_stdout_yaml"];
  };

  tls = mkProvider {
    type = "tls";
    version = "4.4.2";
    repository = "hashicorp/terraform-provider-tls";
    hash = "sha256-WWLOvZ+4ikx5y1UMsFkGFpWBe7vAV2CPccbkGaGssXM=";
    modulesHash = "sha256-MTfCu0p90uXltgLgid3IYWYR2ueYqKygVmiFRgpaXzY=";
    description = "OpenTofu provider for TLS keys and certificates";
    skippedTests = [
      (registryUpgrade "internal/provider/data_source_public_key_test.go" "TestPublicKey_dataSource_PEM_UpgradeFromVersion3_4_0")
    ];
  };

  http = mkProvider {
    type = "http";
    version = "3.6.3";
    repository = "hashicorp/terraform-provider-http";
    hash = "sha256-C+z4kXDY6agVRvqlR+3QwLoqNc564zcJj3qdoEMYjiQ=";
    modulesHash = "sha256-TY/hGWaOkgcLreXpv+zY1JYQCBf6BkWRTMnC3AqSA3g=";
    description = "OpenTofu provider for HTTP GET data sources";
  };
}

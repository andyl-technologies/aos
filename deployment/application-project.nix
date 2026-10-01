# Application-owned intent; runtime/provider authority is selected by infra.
let
  requiredFile = environmentVariable: {
    inherit environmentVariable;
    required = true;
  };
in {
  apiVersion = "applications.andyl.com/v1alpha1";
  kind = "ApplicationProject";
  name = "aos-hub-hybrid";
  frameworkVersion = "v1.0.0";
  releaseGroups.native.components = ["aos-hub-native"];
  environments.staging = {
    name = "staging";
    class = "staging";
  };
  capabilities = {};
  components.aos-hub-native = {
    name = "aos-hub-native";
    kind = "cloud-run-service";
    releaseEnabled = true;
    source = {
      rootDirectory = ".";
      buildFlakeAttribute = "container-aos-hub-platform-index";
      releaseBuilder = null;
    };
    protocol = "http";
    public = true;
    # SQL is an authenticated external binding in infra's trusted runtime policy.
    capabilityAliases = [];
    secrets = {
      database-url = requiredFile "HUB_DATABASE_URL_FILE";
      jwt-secret = requiredFile "HUB_JWT_SECRET_FILE";
      instance-seal-key = requiredFile "AOS_HUB_SECRET_KEY_FILE";
      hybrid-ingress-key = requiredFile "HUB_HYBRID_INGRESS_KEY_FILE";
      storage-work-key = requiredFile "HUB_STORAGE_WORK_KEY_FILE";
      route-reservation-keys = requiredFile "HUB_ROUTE_RESERVATION_KEYS_FILE";
      domain-probe-signers = requiredFile "HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE";
      release-receipt-key = requiredFile "HUB_RELEASE_RECEIPT_KEY_FILE";
      channel-receipt-key = requiredFile "HUB_CHANNEL_RECEIPT_KEY_FILE";
      release-publication-keys = requiredFile "HUB_RELEASE_PUBLICATION_KEYS_FILE";
      qualification-keys = requiredFile "HUB_QUALIFICATION_KEYS_FILE";
    };
    environments.staging = {
      target = "gcp-cloud-run";
      enabled = true;
      endpoints.origin = {
        hosts = ["aos-hybrid-origin.staging.andyl.org"];
        paths = ["/*"];
        protection = "standard";
        rateLimitProfile = null;
      };
      regions = ["us-central1"];
      resourceProfile = "hub-staging";
      rolloutProfile = "staging";
      scheduledInvocations = {};
      runtimeEnvironment = {
        HUB_TOPOLOGY = "hybrid";
        HUB_LISTEN = "0.0.0.0:8080";
        HUB_ROOT = "/tmp/aos-hub";
        HUB_EXTERNAL_URL = "https://aos-hybrid.staging.andyl.org";
        HUB_HYBRID_WORKER_URL = "https://aos-hybrid.staging.andyl.org";
        HUB_HYBRID_ORIGIN_URL = "https://aos-hybrid-origin.staging.andyl.org";
        HUB_DEPLOYMENT_ID = "aos-hub-hybrid-staging";
        HUB_DNS_JSON_ENDPOINT = "https://dns.google/resolve";
        HUB_RELEASE_RECEIPT_KEY_ID = "aos-hub-hybrid-staging-release-receipt-v1";
        HUB_CHANNEL_RECEIPT_KEY_ID = "aos-hub-hybrid-staging-channel-receipt-v1";
      };
    };
  };
}

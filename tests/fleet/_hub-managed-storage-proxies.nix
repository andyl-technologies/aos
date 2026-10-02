# Reuse the same bounded body/header formats in the separate Managed pair.
# The runtime substitutes a validated run ID and both actual private VM IPs.
{
  serverCertificate,
  serverPrivateKey,
  managedCleanupLossUpstream ? null,
  managedOciProfileHoldUpstream ? null,
}: let
  nativeRoot = "/var/lib/hybrid-managed-native/@MANAGED_RUN@";
  workerRoot = "/var/lib/hybrid-managed-worker/@MANAGED_RUN@/boundary";
  workerNativeRoot = "/var/lib/hybrid-managed-worker/@MANAGED_RUN@/native-outbound";
  workerNative = import ./_hub-direct-storage-proxies.nix {
    inherit serverCertificate serverPrivateKey;
    nativeRoot = workerNativeRoot;
    nativeListenPort = 4644;
    serverName = "localhost";
    nativeUpstream = "https://@MANAGED_NATIVE_ADDRESS@:4644";
    nativeUpstreamCertificateName = "localhost";
    includeTransferCompletion = true;
  };
  storage = import ./_hub-direct-storage-proxies.nix {
    inherit serverCertificate serverPrivateKey workerRoot managedCleanupLossUpstream managedOciProfileHoldUpstream;
    includeManagedCleanupControls = true;
    nativeRoot = "${nativeRoot}/outbound";
    nativeListenPort = 4643;
    workerListenPort = 4643;
    serverName = "localhost";
    nativeUpstream = "https://@MANAGED_WORKER_ADDRESS@:4643";
    nativeUpstreamCertificateName = "localhost";
    workerUpstream = "https://127.0.0.1:4645";
    workerAdditionalHttp = workerNative.nativeHttp;
  };
in {
  nativeConfiguration = import ./_hub-direct-native-proxy.nix {
    inherit serverCertificate serverPrivateKey;
    observationRoot = "${nativeRoot}/inbound";
    listenPort = 4644;
    serverName = "localhost";
    upstream = "https://127.0.0.1:4646";
    upstreamCertificateName = "localhost";
    includeIssuer = false;
    includeOriginalCorrelation = true;
    storageHttp = storage.nativeHttp;
  };
  workerConfiguration = storage.workerConfiguration;
}

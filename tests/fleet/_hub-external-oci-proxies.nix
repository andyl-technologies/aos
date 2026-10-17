# The dedicated External pair keeps one public origin through stock bootstrap
# and the controlled Native switch. Bodies retain their independent directions.
{
  serverCertificate,
  serverPrivateKey,
}: let
  nativeRoot = "/var/lib/hybrid-native/external-oci/@EXTERNAL_RUN@";
  workerRoot = "/var/lib/hybrid-worker/external-oci/@EXTERNAL_RUN@";
  workerNative = import ./_hub-direct-storage-proxies.nix {
    inherit serverCertificate serverPrivateKey;
    nativeRoot = "${workerRoot}/native-outbound";
    nativeListenPort = 4674;
    serverName = "localhost";
    nativeUpstream = "https://@EXTERNAL_NATIVE_ADDRESS@:4674";
    nativeUpstreamCertificateName = "localhost";
    includeTransferCompletion = true;
  };
  storage = import ./_hub-direct-storage-proxies.nix {
    inherit serverCertificate serverPrivateKey;
    nativeRoot = "${nativeRoot}/outbound";
    workerRoot = "${workerRoot}/boundary";
    nativeListenPort = 4673;
    workerListenPort = 4673;
    serverName = "localhost";
    nativeUpstream = "https://@EXTERNAL_WORKER_ADDRESS@:4673";
    nativeUpstreamCertificateName = "localhost";
    workerUpstream = "https://127.0.0.1:4675";
    externalCopyClosedLossUpstream = "http://127.0.0.1:4678";
    workerAdditionalHttp = workerNative.nativeHttp;
  };
  issuerHttp = ''
    server {
      listen 4677 ssl;
      server_name localhost;
      ssl_certificate ${serverCertificate}/value;
      ssl_certificate_key ${serverPrivateKey}/value;
      client_max_body_size 256k;
      location / {
        proxy_pass https://127.0.0.1:4680;
        proxy_ssl_server_name on;
        proxy_ssl_name localhost;
        proxy_set_header Host $http_host;
        proxy_http_version 1.1;
        proxy_request_buffering on;
        proxy_buffering on;
      }
    }
  '';
in {
  nativeConfiguration = import ./_hub-direct-native-proxy.nix {
    inherit serverCertificate serverPrivateKey;
    observationRoot = "${nativeRoot}/inbound";
    listenPort = 4674;
    serverName = "localhost";
    upstream = "http://127.0.0.1:4676";
    upstreamCertificateName = "localhost";
    includeIssuer = false;
    includeOriginalCorrelation = true;
    storageHttp = storage.nativeHttp + issuerHttp;
  };
  workerConfiguration = storage.workerConfiguration;
}

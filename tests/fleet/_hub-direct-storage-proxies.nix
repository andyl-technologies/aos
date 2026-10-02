# Observe original Native bodies and independently received Worker bodies.
# Fixture routing preserves the configured origin, HMAC and canonical bytes.
{
  serverCertificate,
  serverPrivateKey,
  nativeRoot ? "/var/lib/hybrid-native-outbound",
  workerRoot ? "/var/lib/hybrid-worker-boundary",
  nativeListenPort ? 443,
  workerListenPort ? 443,
  serverName ? "aos.andyl.org",
  nativeUpstream ? "https://worker:443",
  nativeUpstreamCertificateName ? "aos.andyl.org",
  workerUpstream ? "https://127.0.0.1:4443",
  workerUpstreamCertificateName ? "localhost",
  heldExecuteUpstream ? null,
  managedCleanupLossUpstream ? null,
  includeManagedCleanupControls ? false,
  workerAdditionalHttp ? "",
  includeTransferCompletion ? false,
}:
assert heldExecuteUpstream == null || heldExecuteUpstream == "https://localhost:4650";
assert managedCleanupLossUpstream == null || managedCleanupLossUpstream == "http://127.0.0.1:4660";
let
  protectedHeaders = import ./_hub-protected-header-format.nix;
  headerFormat = name: protectedHeaders {
    inherit name;
    includeManagedCleanup = includeManagedCleanupControls;
  };
  format = name: root: extra: ''
    log_format ${name} escape=json
      '{"procedure":"$uri","phase":"$http_x_aos_hybrid_upload_phase",'
      '"status":"$status","request_http_bytes":"$request_length",'
      '"request_body_bytes":"$content_length","response_body_bytes":"$body_bytes_sent",'
      '"response_http_bytes":"$bytes_sent","elapsed_seconds":"$request_time",'
      '"completed_unix_seconds":"$msec",'
      '"upstream_status":"$upstream_status","upstream_seconds":"$upstream_response_time",'
      '"request_id":"$request_id","request_body_file":"$request_body_file",'
      '"response_body_file":"${root}/response-bodies/$request_id",'
      '"method":"$request_method","response_content_type":"$sent_http_content_type",'
      '"request_transfer_encoding":"$http_transfer_encoding",'
      '"response_content_encoding":"$sent_http_content_encoding"${extra}${if includeTransferCompletion then '',"request_completion":"$request_completion","upstream_response_bytes":"$upstream_response_length"'' else ""}}';
  '';
  capture = root: ''
    client_body_in_file_only on;
    client_body_temp_path ${root}/client-body;
    proxy_temp_path ${root}/proxy-temp;
    proxy_store ${root}/response-bodies/$request_id;
    proxy_store_access user:rw;
    proxy_request_buffering on;
    proxy_buffering on;
  '';
  forwarding = upstream: certificateName: ''
    proxy_pass ${upstream};
    proxy_ssl_server_name on;
    proxy_ssl_name ${certificateName};
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    proxy_set_header Host $http_host;
    proxy_http_version 1.1;
  '';
in {
  nativeHttp = ''
    ${format "native_outbound" nativeRoot ""}
    ${headerFormat "native_outbound_headers"}
    server {
      listen ${toString nativeListenPort} ssl;
      server_name ${serverName};
      ssl_certificate ${serverCertificate}/value;
      ssl_certificate_key ${serverPrivateKey}/value;
      client_max_body_size 0;
      access_log ${nativeRoot}/requests.jsonl native_outbound;
      access_log ${nativeRoot}/protected-headers.jsonl native_outbound_headers;
      ${
        if heldExecuteUpstream == null
        then ""
        else ''
          # Baseline and loaded traffic use this same unarmed listener. It may
          # hold one exact signed index original; capture and identity stay intact.
          location = /_internal/storage/v1/execute {
            ${capture nativeRoot}
            ${forwarding heldExecuteUpstream "localhost"}
            proxy_set_header x-aos-fleet-request-id $request_id;
          }
        ''
      }
      ${
        if managedCleanupLossUpstream == null
        then ""
        else ''
          # This initial unarmed listener may lose one fully consumed, verified
          # cleanup reply. All original request bytes and correlation stay intact.
          location = /_internal/storage/managed-oci-cleanup/v1 {
            ${capture nativeRoot}
            ${forwarding managedCleanupLossUpstream "localhost"}
            proxy_set_header x-aos-fleet-request-id $request_id;
          }
        ''
      }
      location / {
        ${capture nativeRoot}
        ${forwarding nativeUpstream nativeUpstreamCertificateName}
        # Correlation only; this header grants no authentication or authority.
        proxy_set_header x-aos-fleet-request-id $request_id;
      }
    }
  '';
  workerConfiguration = ''
    user root;
    pid ${workerRoot}/nginx.pid;
    error_log ${workerRoot}/error.log warn;
    events { worker_connections 256; }
    http {
      ${format "worker_storage" workerRoot '',"origin_request_id":"$http_x_aos_fleet_request_id","caller":"$remote_addr"''}
      ${headerFormat "worker_storage_headers"}
      access_log off;
      ${workerAdditionalHttp}
      client_max_body_size 0;
      client_body_temp_path ${workerRoot}/client-body;
      proxy_temp_path ${workerRoot}/proxy-temp;
      fastcgi_temp_path ${workerRoot}/fastcgi-temp;
      uwsgi_temp_path ${workerRoot}/uwsgi-temp;
      scgi_temp_path ${workerRoot}/scgi-temp;
      server {
        listen ${toString workerListenPort} ssl;
        server_name ${serverName};
        ssl_certificate ${serverCertificate}/value;
        ssl_certificate_key ${serverPrivateKey}/value;
        location /_internal/storage/ {
          access_log ${workerRoot}/requests.jsonl worker_storage;
          access_log ${workerRoot}/protected-headers.jsonl worker_storage_headers;
          ${capture workerRoot}
          ${forwarding workerUpstream workerUpstreamCertificateName}
        }
        location / {
          # Public object traffic is not spooled by the metadata observer.
          proxy_store off;
          proxy_request_buffering off;
          proxy_buffering off;
          ${forwarding workerUpstream workerUpstreamCertificateName}
        }
      }
    }
  '';
}

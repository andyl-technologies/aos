# Observe numeric Native HTTP boundaries and retain owner-private body files for
# exact codec classification. Compact controls have a separate private log;
# bearer and cookie credentials are omitted from both logs.
# Both baseline and loaded traffic use the same observation buffering/storage.
{
  serverCertificate,
  serverPrivateKey,
  storageHttp ? "",
  observationRoot ? "/var/lib/hybrid-native-observations",
  listenPort ? 443,
  serverName ? "aos.staging.andyl.org",
  upstream ? "https://127.0.0.1:4443",
  upstreamCertificateName ? "aos.staging.andyl.org",
  includeIssuer ? true,
  includeOriginalCorrelation ? false,
}: let
  protectedHeaders = import ./_hub-protected-header-format.nix;
in ''
  user root;
  pid ${observationRoot}/nginx.pid;
  error_log ${observationRoot}/error.log warn;
  events { worker_connections 256; }
  http {
    ${protectedHeaders "native_protected_headers"}
    log_format native_control escape=json
      '{"procedure":"$uri","phase":"$http_x_aos_hybrid_upload_phase",'
      '"status":"$status","request_http_bytes":"$request_length",'
      '"request_body_bytes":"$content_length","response_body_bytes":"$body_bytes_sent",'
      '"response_http_bytes":"$bytes_sent","elapsed_seconds":"$request_time",'
      '"upstream_status":"$upstream_status","upstream_seconds":"$upstream_response_time",'
      '"request_id":"$request_id","request_body_file":"$request_body_file",'
      '"response_body_file":"${observationRoot}/response-bodies/$request_id",'
      '"method":"$request_method","response_content_type":"$sent_http_content_type",'
      '"request_transfer_encoding":"$http_transfer_encoding",'
      '"response_content_encoding":"$sent_http_content_encoding"${if includeOriginalCorrelation then '',"completed_unix_seconds":"$msec","origin_request_id":"$http_x_aos_fleet_request_id","caller":"$remote_addr","request_completion":"$request_completion","upstream_response_bytes":"$upstream_response_length"'' else ""}}';
    access_log ${observationRoot}/requests.jsonl native_control;
    access_log ${observationRoot}/protected-headers.jsonl native_protected_headers;
    # Private body files let the observer classify actual bytes and match the
    # signed envelopes. They are never included in the published numeric ledger.
    client_body_in_file_only on;
    proxy_store ${observationRoot}/response-bodies/$request_id;
    proxy_store_access user:rw;
    client_body_temp_path ${observationRoot}/client-body;
    proxy_temp_path ${observationRoot}/proxy-temp;
    fastcgi_temp_path ${observationRoot}/fastcgi-temp;
    uwsgi_temp_path ${observationRoot}/uwsgi-temp;
    scgi_temp_path ${observationRoot}/scgi-temp;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    ${storageHttp}
    server {
      listen ${toString listenPort} ssl;
      server_name ${serverName};
      ssl_certificate ${serverCertificate}/value;
      ssl_certificate_key ${serverPrivateKey}/value;
      client_max_body_size 0;
      location / {
        proxy_pass ${upstream};
        proxy_ssl_server_name on;
        proxy_ssl_name ${upstreamCertificateName};
        proxy_set_header Host $http_host;
        proxy_http_version 1.1;
        proxy_request_buffering on;
        proxy_buffering on;
      }
    }
    ${if includeIssuer then ''
    # The issuer stays a separate Native process. Observe its bounded grants
    # at the VM boundary as well as the Hub's ordinary metadata controls.
    server {
      listen 8443 ssl;
      server_name localhost;
      ssl_certificate ${serverCertificate}/value;
      ssl_certificate_key ${serverPrivateKey}/value;
      client_max_body_size 256k;
      location / {
        proxy_pass https://127.0.0.1:8444;
        proxy_ssl_server_name on;
        proxy_ssl_name localhost;
        proxy_set_header Host $http_host;
        proxy_http_version 1.1;
        proxy_request_buffering on;
        proxy_buffering on;
      }
    }
    '' else ""}
  }
''

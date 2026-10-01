# Observe original Native bodies and independently received Worker bodies.
# Fixture routing preserves the configured origin, HMAC and canonical bytes.
{
  serverCertificate,
  serverPrivateKey,
}: let
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
      '"response_content_encoding":"$sent_http_content_encoding"${extra}}';
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
  nativeRoot = "/var/lib/hybrid-native-outbound";
  workerRoot = "/var/lib/hybrid-worker-boundary";
in {
  nativeHttp = ''
    ${format "native_outbound" nativeRoot ""}
    server {
      listen 443 ssl;
      server_name aos.andyl.org;
      ssl_certificate ${serverCertificate}/value;
      ssl_certificate_key ${serverPrivateKey}/value;
      client_max_body_size 0;
      access_log ${nativeRoot}/requests.jsonl native_outbound;
      location / {
        ${capture nativeRoot}
        ${forwarding "https://worker:443" "aos.andyl.org"}
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
      access_log off;
      client_max_body_size 0;
      client_body_temp_path ${workerRoot}/client-body;
      proxy_temp_path ${workerRoot}/proxy-temp;
      fastcgi_temp_path ${workerRoot}/fastcgi-temp;
      uwsgi_temp_path ${workerRoot}/uwsgi-temp;
      scgi_temp_path ${workerRoot}/scgi-temp;
      server {
        listen 443 ssl;
        server_name aos.andyl.org;
        ssl_certificate ${serverCertificate}/value;
        ssl_certificate_key ${serverPrivateKey}/value;
        location /_internal/storage/ {
          access_log ${workerRoot}/requests.jsonl worker_storage;
          ${capture workerRoot}
          ${forwarding "https://127.0.0.1:4443" "localhost"}
        }
        location / {
          # Public object traffic is not spooled by the metadata observer.
          proxy_store off;
          proxy_request_buffering off;
          proxy_buffering off;
          ${forwarding "https://127.0.0.1:4443" "localhost"}
        }
      }
    }
  '';
}

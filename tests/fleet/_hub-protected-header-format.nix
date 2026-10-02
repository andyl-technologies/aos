# Retain only compact application controls in a separate private fixture log.
# Bearer, cookie, CSRF and provider authorization headers are never selected.
name: ''
  # Arbitrary query strings may contain credentials. Only the closed OCI
  # upload selectors are retained; every other query stays unsupported.
  map $args ${"$"}${name}_target {
    default "";
    "" $request_uri;
    "~^aos_hybrid_manifest_upload=[0-9a-f]{32}$" $request_uri;
    "~^digest=sha256:[0-9a-f]{64}$" $request_uri;
  }
  map $args ${"$"}${name}_query_class {
    default unsupported;
    "" absent;
    "~^aos_hybrid_manifest_upload=[0-9a-f]{32}$" retained;
    "~^digest=sha256:[0-9a-f]{64}$" retained;
  }
  map ${"$"}${name}_query_class ${"$"}${name}_ingress {
    default "";
    absent $http_x_aos_hybrid_ingress;
    retained $http_x_aos_hybrid_ingress;
  }
  log_format ${name} escape=json
    '{"version":"1","request_id":"$request_id",'
    '"origin_request_id":"$http_x_aos_fleet_request_id",'
    '"path_and_query":"${"$"}${name}_target","query_class":"${"$"}${name}_query_class",'
    '"method":"$request_method",'
    '"phase":"$http_x_aos_hybrid_upload_phase","status":"$status",'
    '"ingress":"${"$"}${name}_ingress",'
    '"request_signature":"$http_x_aos_storage_work_signature",'
    '"reply_signature":"$sent_http_x_aos_storage_work_signature"}';
''

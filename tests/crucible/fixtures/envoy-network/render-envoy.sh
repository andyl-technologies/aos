#!/bin/sh
# Render one router's static Envoy bootstrap. The selected recovery strategy
# changes the real upstream route used by router A.
set -eu

role=$1
strategy=$2
output=$3
retry_limit=${4:-3}
fast_reroute=${5:-true}
network_prefix=${CRUCIBLE_NETWORK_PREFIX:-10.77.0}

case "$retry_limit" in
  0|1|2|3|4|5|6|7|8|9|10|11|12) ;;
  *) echo "invalid retry limit: $retry_limit" >&2; exit 2 ;;
esac
case "$fast_reroute" in
  true|false) ;;
  *) echo "invalid fast reroute setting: $fast_reroute" >&2; exit 2 ;;
esac

case "$role" in
  router-a)
    hop=a
    address=$network_prefix.2
    primary=$network_prefix.3
    backup=$network_prefix.4
    ;;
  router-b)
    hop=b
    address=$network_prefix.3
    primary=$network_prefix.4
    backup=
    ;;
  router-c)
    hop=c
    address=$network_prefix.4
    primary=$network_prefix.5
    backup=
    ;;
  *)
    echo "unknown Envoy role: $role" >&2
    exit 2
    ;;
esac

case "$strategy" in
  retain_and_probe|restart_adjacency) ;;
  withdraw_then_relearn)
    if [ "$role" = router-a ]; then
      primary=$network_prefix.4
      backup=
    fi
    ;;
  recompute_all)
    if [ "$role" = router-a ]; then
      primary=$network_prefix.4
      backup=$network_prefix.3
    fi
    ;;
  unsafe_short_circuit)
    if [ "$role" != router-a ]; then
      echo "unsafe response is only defined for router A" >&2
      exit 2
    fi
    ;;
  *)
    echo "unknown recovery strategy: $strategy" >&2
    exit 2
    ;;
esac

if [ "$strategy" = unsafe_short_circuit ]; then
  route='"direct_response":{"status":200,"body":{"inline_string":"UNSAFE:router-a-bypassed-endpoint"}}'
else
  route='"route":{"cluster":"next_hop","timeout":"3s"}'
fi

if [ "$strategy" != unsafe_short_circuit ] && [ "$retry_limit" -gt 0 ]; then
  route='"route":{"cluster":"next_hop","timeout":"3s","retry_policy":{"retry_on":"connect-failure,reset,5xx","num_retries":'"$retry_limit"'}}'
fi

if [ -n "$backup" ] && [ "$fast_reroute" = true ]; then
  backup_endpoint=$(cat <<EOF
,{"locality":{"region":"backup"},"priority":1,"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"$backup","port_value":8080}}}}]}
EOF
  )
else
  backup_endpoint=
fi

# A's backup must be checked promptly even before it receives routed traffic.
# Envoy otherwise schedules its next initial check after 60 seconds.
cat > "$output" <<EOF
{
  "admin": {
    "address": {"socket_address": {"address": "$address", "port_value": 9901}}
  },
  "static_resources": {
    "listeners": [{
      "name": "ingress_$hop",
      "address": {"socket_address": {"address": "$address", "port_value": 8080}},
      "filter_chains": [{"filters": [{
        "name": "envoy.filters.network.http_connection_manager",
        "typed_config": {
          "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
          "stat_prefix": "ingress_$hop",
          "route_config": {
            "name": "network_recovery",
            "virtual_hosts": [{"name": "service", "domains": ["*"], "routes": [{
              "match": {"prefix": "/"},
              $route,
              "request_headers_to_add": [{"header": {"key": "x-crucible-$hop", "value": "1"}}]
            }]}]
          },
          "http_filters": [{
            "name": "envoy.filters.http.router",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}
          }]
        }
      }]}]
    }],
    "clusters": [{
      "name": "next_hop",
      "type": "STATIC",
      "connect_timeout": "0.250s",
      "lb_policy": "ROUND_ROBIN",
      "health_checks": [{
        "timeout": "1s",
        "interval": "2s",
        "no_traffic_interval": "2s",
        "unhealthy_threshold": 2,
        "healthy_threshold": 1,
        "http_health_check": {"path": "/healthz"}
      }],
      "load_assignment": {
        "cluster_name": "next_hop",
        "endpoints": [{"locality": {"region": "primary"}, "priority": 0,
          "lb_endpoints": [{"endpoint": {"address": {"socket_address": {
            "address": "$primary", "port_value": 8080
          }}}}]
        }$backup_endpoint]
      }
    }]
  }
}
EOF

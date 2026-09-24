# Run the actual AOS-built proxies on loopback to verify the configured path,
# fallback route, and injectable unsafe response before booting five QEMU VMs.
set -eu

export CRUCIBLE_NETWORK_PREFIX=127.77.0
work=$TMPDIR/envoy-network-smoke
export CRUCIBLE_CONTROL_STATE_DIR=$work/control
mkdir -p "$work"
mkdir -p "$work/nginx-temp"
mkdir -p "$CRUCIBLE_CONTROL_STATE_DIR"

stop_processes() {
  for pid in ${control_pid:-} ${a_pid:-} ${b_pid:-} ${c_pid:-} ${east_pid:-}; do
    kill "$pid" 2>/dev/null || :
  done
  for pid in ${control_pid:-} ${a_pid:-} ${b_pid:-} ${c_pid:-} ${east_pid:-}; do
    wait "$pid" 2>/dev/null || :
  done
}
trap stop_processes EXIT HUP INT TERM

cat > "$work/nginx.conf" <<EOF
worker_processes 1;
pid $work/nginx.pid;
error_log $work/nginx.log notice;
events { worker_connections 128; }
http {
  access_log off;
  client_body_temp_path $work/nginx-temp/client-body;
  proxy_temp_path $work/nginx-temp/proxy;
  fastcgi_temp_path $work/nginx-temp/fastcgi;
  uwsgi_temp_path $work/nginx-temp/uwsgi;
  scgi_temp_path $work/nginx-temp/scgi;
  server {
    listen 127.77.0.5:8080;
    location /healthz { return 200 "healthy"; }
    location /probe {
      return 200 "east:\$arg_seq:\$http_x_crucible_a:\$http_x_crucible_b:\$http_x_crucible_c";
    }
  }
}
EOF

nginx -p "$work/" -c "$work/nginx.conf" -e "$work/nginx.log" \
  -g 'daemon off; master_process off;' >"$work/east.log" 2>&1 &
east_pid=$!

for role in router-c router-b router-a; do
  bash "$RENDER_ENVOY" "$role" retain_and_probe "$work/$role.json"
  envoy --mode validate --config-path "$work/$role.json" \
    >"$work/$role.validate.log" 2>&1
done
for strategy in withdraw_then_relearn recompute_all restart_adjacency; do
  bash "$RENDER_ENVOY" router-a "$strategy" "$work/router-a-$strategy.json"
  envoy --mode validate --config-path "$work/router-a-$strategy.json" \
    >"$work/router-a-$strategy.validate.log" 2>&1
done

envoy --disable-hot-restart --config-path "$work/router-c.json" \
  --log-level warning >"$work/router-c.log" 2>&1 &
c_pid=$!

wait_for_health() {
  address=$1
  attempts=0
  until [ "$(curl --noproxy '*' --silent --output /dev/null \
    --write-out '%{http_code}' --connect-timeout 1 --max-time 2 \
    "http://$address:8080/healthz" 2>/dev/null || :)" = 200 ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 80 ]; then
      echo "router $address did not become healthy" >&2
      return 1
    fi
    sleep 0.25
  done
}

wait_for_health 127.77.0.4
envoy --disable-hot-restart --config-path "$work/router-b.json" \
  --log-level warning >"$work/router-b.log" 2>&1 &
b_pid=$!
wait_for_health 127.77.0.3
envoy --disable-hot-restart --config-path "$work/router-a.json" \
  --log-level warning >"$work/router-a.log" 2>&1 &
a_pid=$!

probe() {
  curl --noproxy '*' --silent --show-error --fail \
    --connect-timeout 1 --max-time 4 \
    "http://127.77.0.2:8080/probe?seq=$1" 2>/dev/null || :
}

wait_for_body() {
  expected=$1
  sequence=$2
  attempts=0
  while :; do
    observed=$(probe "$sequence")
    if [ "$observed" = "$expected" ]; then
      return
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 80 ]; then
      echo "route expected '$expected', last received '$observed'" >&2
      return 1
    fi
    sleep 0.25
  done
}

wait_for_body 'east:1:1:1:1' 1

# The guest's direct primary probe addresses B, so it exercises both primary
# segments before A changes its Envoy route.
primary_body=$(curl --noproxy '*' --connect-timeout 1 --max-time 1 \
  --silent --show-error --fail http://127.77.0.3:8080/probe)
test "$primary_body" = 'east:::1:1'

python3 "$TRAFFIC_PY" control >"$work/control.log" 2>&1 &
control_pid=$!
east_control_url=http://127.77.0.4:8080/control

wait_for_control_status() {
  expected=$1
  boundary=$2
  attempts=0
  while :; do
    observed=$(curl --noproxy '*' --silent --output /dev/null \
      --write-out '%{http_code}' "http://127.77.0.2:9090/$boundary" || :)
    if [ "$observed" = "$expected" ]; then
      return
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 40 ]; then
      echo "control $boundary expected $expected, received $observed" >&2
      return 1
    fi
    sleep 0.25
  done
}

wait_for_control_status 425 converged
east_status=$(curl --noproxy '*' --interface 127.77.0.5 --silent \
  --output /dev/null --write-out '%{http_code}' \
  "$east_control_url/converged")
test "$east_status" = 425
rejected=$(curl --noproxy '*' --silent --output /dev/null \
  --write-out '%{http_code}' --request POST --data '' \
  http://127.77.0.2:9090/ready/transport/router-b)
test "$rejected" = 425
curl --noproxy '*' --silent --show-error --fail --request POST \
  --data '' http://127.77.0.2:9090/converged >/dev/null
wait_for_control_status 204 converged
east_status=$(curl --noproxy '*' --interface 127.77.0.5 --silent \
  --output /dev/null --write-out '%{http_code}' \
  "$east_control_url/converged")
test "$east_status" = 204

acknowledge_peer() {
  phase=$1
  peer=$2
  if [ "$peer" = traffic-east ]; then
    curl --noproxy '*' --interface 127.77.0.5 --silent --show-error \
      --fail --request POST --data '' \
      "$east_control_url/ready/$phase/$peer" >/dev/null
  else
    curl --noproxy '*' --silent --show-error --fail --request POST \
      --data '' "http://127.77.0.2:9090/ready/$phase/$peer" >/dev/null
  fi
}

for peer in router-b router-c traffic-east; do
  acknowledge_peer transport "$peer"
  wait_for_control_status 204 "ready/transport/$peer"
done
wait_for_control_status 425 followup-ready
rejected=$(curl --noproxy '*' --silent --output /dev/null \
  --write-out '%{http_code}' --request POST --data '' \
  http://127.77.0.2:9090/followup-ready)
test "$rejected" = 425
wait_for_control_status 425 transport-applied
touch "$CRUCIBLE_CONTROL_STATE_DIR/transport-applied"
wait_for_control_status 204 transport-applied
curl --noproxy '*' --silent --show-error --fail --request POST \
  --data '' http://127.77.0.2:9090/followup-ready >/dev/null
wait_for_control_status 204 followup-ready
for peer in router-b router-c traffic-east; do
  acknowledge_peer followup "$peer"
  wait_for_control_status 204 "ready/followup/$peer"
done

kill "$b_pid"
wait "$b_pid" 2>/dev/null || :
b_pid=
wait_for_body 'east:2:1::1' 2

kill "$a_pid"
wait "$a_pid" 2>/dev/null || :
a_pid=
envoy --disable-hot-restart \
  --config-path "$work/router-a-withdraw_then_relearn.json" \
  --log-level warning >"$work/router-a-withdraw.log" 2>&1 &
a_pid=$!
wait_for_body 'east:3:1::1' 3

kill "$a_pid"
wait "$a_pid" 2>/dev/null || :
a_pid=
bash "$RENDER_ENVOY" router-a unsafe_short_circuit "$work/router-a-unsafe.json"
envoy --mode validate --config-path "$work/router-a-unsafe.json" \
  >"$work/router-a-unsafe.validate.log" 2>&1
envoy --disable-hot-restart --config-path "$work/router-a-unsafe.json" \
  --log-level warning >"$work/router-a-unsafe.log" 2>&1 &
a_pid=$!
wait_for_body 'UNSAFE:router-a-bypassed-endpoint' 4

mkdir -p "$out"
cp "$work"/*.log "$out/"
printf '%s\n' PASS > "$out/result"

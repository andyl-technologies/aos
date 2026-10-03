# The VM supplies AOS-built tools and the real packaged flight binary.
set -eu

garage_root=/tmp/campaign-storage-garage
garage_config="$garage_root/garage.toml"
mkdir -p "$garage_root/meta" "$garage_root/data"
cat > "$garage_config" <<EOF
metadata_dir = "$garage_root/meta"
data_dir = "$garage_root/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "1799bccfd7411eddcf9ebd316bc1f5287ad12a68094e1c6ac6abde7e6feae1ec"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
root_domain = ".s3.garage.localhost"
EOF

"$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" server > "$garage_root/server.log" 2>&1 &
garage_pid=$!
cleanup() {
    if "$CRUCIBLE_STORAGE_KILL" -0 "$garage_pid" 2>/dev/null; then
        "$CRUCIBLE_STORAGE_KILL" -CONT "$garage_pid" 2>/dev/null || true
        "$CRUCIBLE_STORAGE_KILL" "$garage_pid" 2>/dev/null || true
        wait "$garage_pid" 2>/dev/null || true
    fi
    cat "$garage_root/server.log"
}
trap cleanup EXIT HUP INT TERM

ready=false
for attempt in $(seq 1 60); do
    if "$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" status > "$garage_root/status.log" 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
test "$ready" = true
node_id=$("$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" node id -q | cut -d@ -f1)
test -n "$node_id"
"$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" layout assign -z dc1 -c 1G "$node_id"
"$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" layout apply --version 1
"$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" key create crucible-recovery > "$garage_root/key.out"
export AWS_ACCESS_KEY_ID=$(awk -F': *' '/Key ID/ {print $2}' "$garage_root/key.out" | tr -d ' ')
export AWS_SECRET_ACCESS_KEY=$(awk -F': *' '/Secret key/ {print $2}' "$garage_root/key.out" | tr -d ' ')
test -n "$AWS_ACCESS_KEY_ID"
test -n "$AWS_SECRET_ACCESS_KEY"
"$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" bucket create crucible-recovery
"$CRUCIBLE_STORAGE_GARAGE" -c "$garage_config" bucket allow --read --write --owner \
    crucible-recovery --key crucible-recovery

# Local loopback is the isolated availability fixture. HTTPS trust/rotation is
# independently covered by the existing live leaf conformance flight.
export AWS_REGION=garage
export AWS_EC2_METADATA_DISABLED=true
export CRUCIBLE_S3_TEST_ENDPOINT=http://127.0.0.1:3900
export CRUCIBLE_S3_TEST_BUCKET=crucible-recovery
export CRUCIBLE_S3_TEST_PREFIX=packaged-paused-recovery
export CRUCIBLE_S3_TEST_GARAGE_PID="$garage_pid"
export CRUCIBLE_S3_TEST_KILL="$CRUCIBLE_STORAGE_KILL"

selector=packaged::guest_choice::storage_recovery::public_exact_paused_guest_recovers_from_s3_outage_and_expired_credentials
"$CRUCIBLE_STORAGE_FLIGHT" --ignored --list > "$garage_root/tests.log"
grep -Fqx "$selector: test" "$garage_root/tests.log"
"$CRUCIBLE_STORAGE_FLIGHT" --ignored --exact "$selector" --nocapture \
    > "$CRUCIBLE_STORAGE_FLIGHT_LOG" 2>&1
cat "$CRUCIBLE_STORAGE_FLIGHT_LOG"

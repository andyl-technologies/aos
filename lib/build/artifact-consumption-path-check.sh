set -euo pipefail
export LC_ALL=C

config=$1
output=$2

fail() {
  printf 'artifact consumption audit: %s\n' "$1" >&2
  exit 1
}

consumer=$(jq -er '.consumer.artifact.store_path + .consumer.path' "$config")
provider=$(jq -er '.provider.artifact.store_path + .provider.path' "$config")
mechanism=$(jq -er .mechanism "$config")

[[ -f $consumer ]] || fail "consumer is not a regular file: $consumer"
[[ -f $provider ]] || fail "provider is not a regular file: $provider"

jq -e '.contract.arguments | all(index("\u0000") | not)' "$config" >/dev/null \
  || fail "invocation arguments cannot contain NUL bytes"
mapfile -d '' -t arguments < <(jq -jer '.contract.arguments[] | ., "\u0000"' "$config")
case $mechanism in
  runtime-plugin-load|helper-execution|immutable-data-input)
    program=$consumer
    jq -e --arg provider "$provider" '.contract.arguments | index($provider) != null' \
      "$config" >/dev/null \
      || fail "$mechanism arguments do not name the exact provider"
    ;;
  build-tool-execution)
    program=$provider
    ;;
  *) fail "unsupported observed path mechanism '$mechanism'" ;;
esac
[[ -x $program ]] || fail "invoked program is not executable: $program"

set +e
strace -f -qq -yy -e trace=execve,openat,read,mmap -o trace.log -- \
  "$program" "${arguments[@]}" > stdout.bin 2> stderr.log
exit_code=$?
set -e
[[ $exit_code -eq 0 ]] || {
  cat stderr.log >&2
  fail "observed invocation exited with status $exit_code"
}

escaped_provider=$(printf '%s' "$provider" | sed 's/[][\\.^$*+?{}|()]/\\&/g')
case $mechanism in
  runtime-plugin-load)
    grep -E "openat\\([^,]+, \"$escaped_provider\".*\\) += [0-9]+(<[^>]+>)?$" \
      trace.log >/dev/null \
      || fail "$mechanism did not successfully open the exact provider"
    grep -E "mmap\\(.*PROT_EXEC.*[0-9]+<$escaped_provider>.*\\) += (0x[0-9a-f]+|[0-9]+)$" \
      trace.log >/dev/null \
      || fail "$mechanism did not map an executable segment from the exact provider"
    ;;
  immutable-data-input)
    grep -E "openat\\([^,]+, \"$escaped_provider\".*\\) += [0-9]+(<[^>]+>)?$" \
      trace.log >/dev/null \
      || fail "$mechanism did not successfully open the exact provider"
    grep -E "read\\([0-9]+<$escaped_provider>,.*\\) += [1-9][0-9]*$" \
      trace.log >/dev/null \
      || fail "$mechanism did not successfully read from the exact provider"
    ;;
  helper-execution|build-tool-execution)
    grep -E "execve\\(\"$escaped_provider\".*\\) += 0$" trace.log >/dev/null \
      || fail "$mechanism did not successfully execute the exact provider"
    ;;
esac

actual_output="sha256:$(sha256sum stdout.bin | cut -d ' ' -f 1)"
expected_output=$(jq -er .contract.output_sha256 "$config")
[[ $actual_output == "$expected_output" ]] \
  || fail "invocation output digest '$actual_output' does not match '$expected_output'"

consumer_digest=$(sha256sum "$consumer" | cut -d ' ' -f 1)
provider_digest=$(sha256sum "$provider" | cut -d ' ' -f 1)
if [[ $mechanism == build-tool-execution ]]; then
  [[ $actual_output == "sha256:$consumer_digest" ]] \
    || fail "build-tool output does not reproduce the exact consumer file"
  retained=false
else
  retained=true
fi

temporary_output="$output.with-newline"
jq -cS \
  --arg consumer_sha256 "sha256:$consumer_digest" \
  --arg provider_sha256 "sha256:$provider_digest" \
  --argjson exit_code "$exit_code" \
  --arg output_sha256 "$actual_output" \
  --argjson retained "$retained" \
  '.consumer.sha256 = $consumer_sha256
   | .provider.sha256 = $provider_sha256
   | .observation = {
       arguments: .contract.arguments,
       exit_code: $exit_code,
       output_sha256: $output_sha256,
       provider_access_observed: true,
       provider_retained_by_consumer: $retained
     }' \
  "$config" > "$temporary_output"

output_size=$(stat -c %s "$temporary_output")
[[ $output_size -gt 1 ]] || fail "canonical evidence output is empty"
truncate -s $((output_size - 1)) "$temporary_output"
mv "$temporary_output" "$output"

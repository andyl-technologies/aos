# Executes the unchanged presentation case as an unprivileged guest identity.
set -euo pipefail
umask 077
unset LD_LIBRARY_PATH

# The harness's /tmp is tmpfs. Fixtures belong on the writable ext4 disk.
mount -o remount,rw /
fixture_root=$(mktemp -d /var/terrane-surface-presentation.XXXXXXXX)
trap 'rm -rf -- "$fixture_root"' EXIT
test "$(findmnt --noheadings --output FSTYPE --target "$fixture_root")" = ext4
chmod 0755 "$fixture_root"
mkdir "$fixture_root/storage" "$fixture_root/evidence"
chown 840:840 "$fixture_root/storage" "$fixture_root/evidence"
chmod 0700 "$fixture_root/storage" "$fixture_root/evidence"

export src=@SOURCE@
export TERRANE_SURFACE_TEST_IMAGE=@IMAGE@
export TMPDIR="$fixture_root/storage"
export TERRANE_PRESENTATION_EVIDENCE="$fixture_root/evidence"

cat > "$fixture_root/run-case" <<'GUEST_CASE'
set -euo pipefail
cd "$src/crates"

python3 - <<'PY'
import json
import os
import pathlib

assert os.getuid() == os.geteuid() == 840
assert os.getgid() == os.getegid() == 840
assert os.getgroups() == []
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
for name in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
    assert int(status[name].strip(), 16) == 0, name
assert status['NoNewPrivs'].strip() == '1'
print(json.dumps({'uid': os.getuid(), 'gid': os.getgid(),
                  'capabilities': {name: status[name].strip() for name in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']},
                  'no_new_privileges': True, 'fixture': os.environ['TMPDIR']}))
PY

python3 "$src/tests/terrane/surface_test_image.py" \
    "$src/tests/terrane/native_sdk_test_image.py" --verify "$TERRANE_SURFACE_TEST_IMAGE"
binary="$TERRANE_SURFACE_TEST_IMAGE/targets/surface_runtime/bin/terrane-native-sdk-tests"
case_name=sdk_presents_attribute_ownership_canonical_times_and_filtered_xattrs
"$binary" --list > "$TERRANE_PRESENTATION_EVIDENCE/inventory.log"
python3 "$src/tests/terrane/check_native_gate.py" inventory \
    "$TERRANE_PRESENTATION_EVIDENCE/inventory.log" "[\"$case_name\"]"

if ! "$binary" "$case_name" --exact --ignored > "$TERRANE_PRESENTATION_EVIDENCE/execution.log" 2>&1; then
    cat "$TERRANE_PRESENTATION_EVIDENCE/execution.log"
    exit 1
fi
python3 "$src/tests/terrane/check_native_gate.py" execution \
    "$TERRANE_PRESENTATION_EVIDENCE/execution.log" "[\"$case_name\"]"
python3 - <<'PY'
import hashlib
import json
import os
import pathlib
import re

evidence = pathlib.Path(os.environ['TERRANE_PRESENTATION_EVIDENCE'])
output = (evidence / 'execution.log').read_text()
case = 'sdk_presents_attribute_ownership_canonical_times_and_filtered_xattrs'
assert re.findall(r'^test (.+) \.\.\. ok$', output, re.MULTILINE) == [case]
assert len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', output, re.MULTILINE)) == 1
image = pathlib.Path(os.environ['TERRANE_SURFACE_TEST_IMAGE'])
binary = image / 'targets/surface_runtime/libexec/terrane-native-sdk-tests'
print(json.dumps({'case': case, 'passed': 1, 'ignored': 0,
                  'image': str(image), 'source': os.environ['src'],
                  'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'identity_sha256': hashlib.sha256((image / 'share/identity.json').read_bytes()).hexdigest()}))
PY
python3 "$src/tests/terrane/surface_test_image.py" \
    "$src/tests/terrane/native_sdk_test_image.py" --verify "$TERRANE_SURFACE_TEST_IMAGE"
GUEST_CASE
chmod 0644 "$fixture_root/run-case"

setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
    --inh-caps=-all --ambient-caps=-all --no-new-privs \
    bash "$fixture_root/run-case"
printf '%s\n' 'PASS: unchanged SDK presentation case on ext4 as UID 840 with empty capabilities'

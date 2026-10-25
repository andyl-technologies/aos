# shellcheck shell=bash
# Exercises every original socket case as the guest's unprivileged publisher.
set -euo pipefail

if [ "$#" -ne 3 ] || [ "$EUID" -ne 0 ]; then
  printf '%s\n' 'native socket units require the guest supervisor and three inputs' >&2
  exit 1
fi

image=$1
unit_root=$2
setpriv=$3

mkdir -- "$unit_root"
test "$(findmnt --noheadings --output FSTYPE --target "$unit_root")" = ext4
printf '%s\n' 'SOCKET_UNIT_FILESYSTEM ext4'
chown 841:845 "$unit_root"
chmod 0700 "$unit_root"
trap 'rm -f -- "$unit_root/result.log"; rmdir -- "$unit_root"' EXIT
export TMPDIR="$unit_root"

executed=0
while IFS= read -r socket_case; do
  if ! "$setpriv" --reuid 841 --regid 845 --clear-groups --bounding-set=-all \
    --inh-caps=-all --ambient-caps=-all --no-new-privs \
    "$BASH" -c '
      set -euo pipefail
      identity_fields=0
      capability_fields=0
      group_fields=0
      privilege_fields=0
      while IFS=: read -r key value; do
        case "$key" in
          Uid)
            [[ "$value" =~ ^[[:space:]]*841[[:space:]]+841[[:space:]]+841[[:space:]]+841[[:space:]]*$ ]]
            identity_fields=$((identity_fields + 1))
            ;;
          Gid)
            [[ "$value" =~ ^[[:space:]]*845[[:space:]]+845[[:space:]]+845[[:space:]]+845[[:space:]]*$ ]]
            identity_fields=$((identity_fields + 1))
            ;;
          CapInh|CapPrm|CapEff|CapBnd|CapAmb)
            [[ "$value" =~ ^[[:space:]]*0000000000000000[[:space:]]*$ ]]
            capability_fields=$((capability_fields + 1))
            ;;
          Groups)
            [[ "$value" =~ ^[[:space:]]*$ ]]
            group_fields=$((group_fields + 1))
            ;;
          NoNewPrivs)
            [[ "$value" =~ ^[[:space:]]*1[[:space:]]*$ ]]
            privilege_fields=$((privilege_fields + 1))
            ;;
        esac
      done < /proc/self/status
      [ "$identity_fields" -eq 2 ]
      [ "$capability_fields" -eq 5 ]
      [ "$group_fields" -eq 1 ]
      [ "$privilege_fields" -eq 1 ]
      printf "%s\n" "SOCKET_UNIT_IDENTITY uid=841 gid=845 groups=none caps=zero nnp=1"
      exec "$@"
    ' socket-unit "$image/bin/terrane_linux" --exact "$socket_case" --nocapture \
    > "$unit_root/result.log" 2>&1; then
    cat "$unit_root/result.log"
    exit 1
  fi

  cat "$unit_root/result.log"
  case "$(cat "$unit_root/result.log")" in
    *'test result: ok. 1 passed; 0 failed; 0 ignored;'*) ;;
    *) exit 1 ;;
  esac
  printf 'SOCKET_UNIT_PASS %s\n' "$socket_case"
  executed=$((executed + 1))
done < "$image/share/native-socket-cases"

[ "$executed" -eq 12 ]
printf '%s\n' 'PASS twelve actual native socket custody cases under the ordinary publisher identity'

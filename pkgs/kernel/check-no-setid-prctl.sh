# This private Linux 7.2.3 ABI must not collide with another prctl operation.
set -eu

header=$1

if [ ! -r "$header" ]; then
  echo "cannot read prctl UAPI header: $header" >&2
  exit 1
fi

set_definitions=$(grep -Ec '^#define[[:space:]]+PR_SET_AOS_NO_SETID[[:space:]]+82([[:space:]]|$)' "$header" || true)
get_definitions=$(grep -Ec '^#define[[:space:]]+PR_GET_AOS_NO_SETID[[:space:]]+83([[:space:]]|$)' "$header" || true)
set_names=$(grep -Ec '^#define[[:space:]]+PR_SET_AOS_NO_SETID[[:space:]]+' "$header" || true)
get_names=$(grep -Ec '^#define[[:space:]]+PR_GET_AOS_NO_SETID[[:space:]]+' "$header" || true)

if [ "$set_definitions" -ne 1 ] || [ "$set_names" -ne 1 ]; then
  echo "PR_SET_AOS_NO_SETID must be prctl operation 82" >&2
  exit 1
fi

if [ "$get_definitions" -ne 1 ] || [ "$get_names" -ne 1 ]; then
  echo "PR_GET_AOS_NO_SETID must be prctl operation 83" >&2
  exit 1
fi

for operation in 82 83; do
  definitions=$(grep -Ec "^#define[[:space:]]+PR_[A-Z0-9_]+[[:space:]]+$operation([[:space:]]|\$)" "$header" || true)

  if [ "$definitions" -ne 1 ]; then
    echo "prctl operation $operation has $definitions definitions; expected one" >&2
    exit 1
  fi
done

#!@bash@/bin/bash
set -euo pipefail

registration=/usr/lib/aos/nix-registration
digest_file=/usr/lib/aos/nix-registration.sha256

# Host verification reads immutable store documents before the native host
# graph can converge the database. Hydrate only the image's exact stream here.
[ -f "$registration" ] && [ -f "$digest_file" ] || {
  echo "aos-host-store-seed: image registration or digest is missing" >&2
  exit 1
}
expected=$(@coreutils@/bin/cat "$digest_file")
if [[ ${#expected} != 64 || "$expected" == *[!0-9a-f]* ]]; then
  echo "aos-host-store-seed: image registration digest is malformed" >&2
  exit 1
fi
actual=$(@coreutils@/bin/sha256sum "$registration")
if [ "${actual%% *}" != "$expected" ]; then
  echo "aos-host-store-seed: image registration digest does not match" >&2
  exit 1
fi

# This bootstrap must work independently of daemon admission and of the
# /etc/nix configuration that the authenticated host graph supplies later.
@nix@/bin/nix-store --store local --option build-users-group "" --init
@nix@/bin/nix-store --store local --option build-users-group "" --load-db < "$registration"

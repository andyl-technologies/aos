# Prepare a selected Cargo workspace from the checked-in full workspace lock.
members:
if members == []
then throw "Cargo workspace selection must contain at least one member"
else ''
  if ! grep -qx 'members = \[' Cargo.toml; then
    echo 'Cargo workspace member list has an unexpected shape' >&2
    exit 1
  fi
  sed '/^members = \[$/,/^\]$/c\
  members = ${builtins.toJSON members}
  ' Cargo.toml > Cargo.toml.reduced
  mv Cargo.toml.reduced Cargo.toml

  # Cargo keeps one lockfile for the full workspace. Resolve the selected
  # members against the pinned, offline vendor closure before frozen builds.
  cargo metadata --offline --format-version 1 > /dev/null
''

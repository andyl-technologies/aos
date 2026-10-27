# Prepare a selected Cargo workspace from the checked-in full workspace lock.
members: let
  selectedMembers = builtins.toJSON members;
in
  if members == []
  then throw "Cargo workspace selection must contain at least one member"
  else ''
    if ! grep -qx 'members = \[' Cargo.toml; then
      echo 'Cargo workspace member list has an unexpected shape' >&2
      exit 1
    fi
    # A reduced workspace has its own explicit package selection. Its defaults
    # must not refer to members removed by the source filter.
    sed -e '/^members = \[$/,/^\]$/c\
    members = ${selectedMembers}
    ' -e '/^default-members = \[$/,/^\]$/c\
    default-members = ${selectedMembers}
    ' Cargo.toml > Cargo.toml.reduced
    mv Cargo.toml.reduced Cargo.toml

    # Cargo keeps one lockfile for the full workspace. Resolve the selected
    # members against the pinned, offline vendor closure before frozen builds.
    cargo metadata --offline --format-version 1 > /dev/null
  ''

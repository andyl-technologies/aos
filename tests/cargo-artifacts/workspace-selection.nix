##! Checks reduced workspaces with and without an explicit default selection.
{pkgs}: let
  prepareWorkspace = import ../../stdenv/cargo-workspace.nix;
in
  pkgs.mkDerivation {
    pname = "cargo-workspace-selection-check";
    version = "1";
    src = null;
    buildDeps = [pkgs.rust pkgs.jq];
    phases = [
      {
        name = "check";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo-home"
          mkdir -p "$CARGO_HOME"

          for defaults in explicit implicit; do
            mkdir -p "$TMPDIR/$defaults/selected/src"
            cd "$TMPDIR/$defaults"
            cat > Cargo.toml <<'EOF'
          [workspace]
          resolver = "2"
          members = [
            "selected",
            "excluded",
          ]
          EOF
            if [ "$defaults" = explicit ]; then
              cat >> Cargo.toml <<'EOF'
          default-members = [
            "excluded",
          ]
          EOF
            fi
            cat > selected/Cargo.toml <<'EOF'
          [package]
          name = "workspace-selection-fixture"
          version = "0.1.0"
          edition = "2024"
          EOF
            printf '%s\n' '//! Exercises a filtered workspace member.' > selected/src/lib.rs

            # The excluded manifest is deliberately absent, as in a filtered
            # production source. Cargo must resolve only the selected member.
            ${prepareWorkspace ["selected"]}
            if [ "$defaults" = implicit ]; then
              ! grep -q '^default-members' Cargo.toml
            fi
            cargo metadata --frozen --offline --format-version 1 > metadata.json
            jq -e '
              .workspace_members == .workspace_default_members
              and (.workspace_members | length) == 1
              and (.packages | length) == 1
              and .packages[0].name == "workspace-selection-fixture"
            ' metadata.json > /dev/null
          done

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }

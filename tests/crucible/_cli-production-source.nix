# Production CLI sources exclude actor/backend fixtures in test fragment files.
{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/control/crucible-cli/src/main.rs;
  fragmentDirs = [../../crates/crucible/control/crucible-cli/src/cli];
  includeTests = false;
}

##! Fixed matching G/H content selection for private Rust helper mechanics.
##!
##! The generated header is compile-time DATA, not an execution credential.
##! Kernel fs-verity and enforcing image/backing observations remain runtime
##! prerequisites and must never be replaced with these full-file SHA256 values.
{
  mkDerivation,
  coreutils,
  git,
  aos-git-helper,
}: let
  helperProgram = "${aos-git-helper}/libexec/aos-git-helper";
  gitProgram = "${git}/bin/git";
in
  assert git.pname == "git" && git.version == "2.55.0";
    mkDerivation {
      pname = "aos-git-helper-images";
      version = "1";
      src = null;
      buildDeps = [coreutils];
      runtimeDeps = [aos-git-helper git];
      propagatedDeps = [];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            header="$out/selected-images.rs"

            # Hash installed, already-stripped package bytes with AOS tools.
            emit_digest() {
              constant_name=$1
              image_path=$2
              digest_record=$(sha256sum "$image_path")
              digest_hex=''${digest_record%% *}
              test "''${#digest_hex}" -eq 64

              printf 'pub(super) const %s: [u8; 32] = [' "$constant_name"
              digest_position=1
              while test "$digest_position" -le 63; do
                digest_end=$((digest_position + 1))
                digest_byte=$(printf '%s' "$digest_hex" | cut -c "$digest_position-$digest_end")
                printf '0x%s,' "$digest_byte"
                digest_position=$((digest_position + 2))
              done
              printf '];\n'
            }

            {
              printf '%s\n' 'pub(super) const HELPER_PATH: &str = ${builtins.toJSON helperProgram};'
              printf '%s\n' 'pub(super) const GIT_PATH: &str = ${builtins.toJSON gitProgram};'
              emit_digest HELPER_CONTENT_SHA256 '${helperProgram}'
              emit_digest GIT_CONTENT_SHA256 '${gitProgram}'
            } > "$header"
            chmod 0444 "$header"
          '';
        }
      ];

      passthru = {
        inherit helperProgram gitProgram;
      };

      meta = {
        description = "Compile-time matching AOS Git helper content selection";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }

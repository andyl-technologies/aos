# Invoked explicitly with the selected AOS Bash and build-tool PATH.
set -euo pipefail
export LC_ALL=C
export MTOOLS_SKIP_CHECK=1

if [ "$#" -ne 2 ]; then
  echo 'usage: populate-esp SOURCE_DIRECTORY FAT_IMAGE' >&2
  exit 2
fi

source_directory=$(realpath -e -- "$1")
image=$(realpath -e -- "$2")
[ -d "$source_directory" ] && [ -f "$image" ]
manifest_directory=$(mktemp -d)
trap 'rm -rf -- "$manifest_directory"' EXIT

# Follow retained artifact aliases, but reject dangling links, loops, and
# special files before changing the FAT image. Records stay NUL-delimited.
find -L "$source_directory" -mindepth 1 -printf '%y\t%P\0' > "$manifest_directory/entries"
while IFS= read -r -d '' entry; do
  case "${entry%%$'\t'*}" in
    d|f) ;;
    *) echo "unsupported ESP source entry: ${entry#*$'\t'}" >&2; exit 1 ;;
  esac
done < "$manifest_directory/entries"

find -L "$source_directory" -mindepth 1 -type d -printf '%P\0' \
  | sort -z > "$manifest_directory/directories"
find -L "$source_directory" -type f -printf '%s\t%P\0' \
  | sort -z -t $'\t' -k1,1nr -k2 > "$manifest_directory/files"

# Parent paths precede descendants. Large files receive contiguous allocation
# first; full relative paths break size ties independently of source traversal.
while IFS= read -r -d '' directory; do
  mmd -i "$image" "::/$directory"
done < "$manifest_directory/directories"

while IFS= read -r -d '' entry; do
  relative_path=${entry#*$'\t'}
  mcopy -i "$image" "$source_directory/$relative_path" "::/$relative_path" < /dev/null
done < "$manifest_directory/files"

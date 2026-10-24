# Projects provider-rendered configuration with its exact image modes.
set -eu

configuration_root=$1
destination_root=$2
json_tool=$3

find "$configuration_root/etc" -type f -print | while IFS= read -r configuration_file; do
    relative_path=${configuration_file#"$configuration_root"/}
    destination="$destination_root/$relative_path"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        echo "initrd configuration collides with a platform file: $destination" >&2
        exit 1
    fi

    # An existing image symlink must never redirect projection out of its root.
    parent_path=$(dirname "$relative_path")
    while [ "$parent_path" != . ]; do
        if [ -L "$destination_root/$parent_path" ]; then
            echo "initrd configuration traverses a platform symlink: $parent_path" >&2
            exit 1
        fi
        parent_path=$(dirname "$parent_path")
    done

    file_mode=$("$json_tool" -er --arg path "/$relative_path" '.[$path]' "$configuration_root/modes.json")
    mkdir -p "$(dirname "$destination")"
    cp "$configuration_file" "$destination"
    chmod -- "$file_mode" "$destination"
done

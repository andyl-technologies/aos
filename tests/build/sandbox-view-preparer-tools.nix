# Executes the final private images after their package's reference scrubbing.
{pkgs, ...}: let
  tools = pkgs.aos-sandbox-view-preparer-tools;
in
  pkgs.runCommand "sandbox-view-preparer-tools-check" {
    buildDeps = [tools pkgs.patchelf];
  } ''
    # These version queries enter every copied image without changing mounts,
    # ownership or filesystem contents. Missing runtime libraries fail here.
    for tool in bash stat mkdir chown findmnt mount umount; do
      ${tools}/libexec/$tool --version > /dev/null
    done

    # Enforcing image labels classify these regular files as libraries. Every
    # non-libc edge must stay within that group, including transitive edges.
    for library in libncursesw.so.6 libmount.so.1 libblkid.so.1 \
        libsmartcols.so.1 libselinux.so.1 libpcre2-8.so.0; do
      test -f "${tools}/lib/$library"
      test ! -L "${tools}/lib/$library"
    done

    for image in ${tools}/libexec/bash ${tools}/libexec/findmnt \
        ${tools}/libexec/mount ${tools}/libexec/umount ${tools}/lib/*; do
      ${pkgs.patchelf}/bin/patchelf --print-needed "$image" > needed
      while IFS= read -r library; do
        case "$library" in
          ${tools}/lib/*)
            test -f "$library"
            test ! -L "$library"
            ;;
          libc.so.6|ld-linux-x86-64.so.2|ld-linux-aarch64.so.1) ;;
          *)
            echo "Unexpected view-preparer dependency: $image -> $library" >&2
            exit 1
            ;;
        esac
      done < needed
    done

    mkdir -p "$out"
    touch "$out/passed"
  ''

# Executes the final private images after their package's reference scrubbing.
{pkgs, ...}: let
  tools = pkgs.aos-sandbox-view-preparer-tools;
in
  pkgs.runCommand "sandbox-view-preparer-tools-check" {
    buildDeps = [tools];
  } ''
    # These version queries enter every copied image without changing mounts,
    # ownership or filesystem contents. Missing runtime libraries fail here.
    for tool in bash stat mkdir chown findmnt mount umount; do
      ${tools}/libexec/$tool --version > /dev/null
    done

    mkdir -p "$out"
    touch "$out/passed"
  ''

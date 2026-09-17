# Pins GNU Make's compiled POSIX recipe shell to its declared runtime Bash.
set -eu
runtime_shell=${1:?expected the runtime shell path}
patched=0

for source in job.c src/job.c; do
  if [ -f "$source" ]; then
    # Both layouts occur in the version ladder. Check the declaration before
    # replacing it so an upstream change cannot silently restore a host shell.
    grep -q 'default_shell.*= "/bin/sh"' "$source"
    sed -i "/default_shell.*=/s|\"/bin/sh\"|\"$runtime_shell\"|" "$source"
    patched=1
  fi
done

test "$patched" -eq 1

##! Renders common login setup for an explicit bootstrap or live profile PATH.
{
  lib,
  path,
}: ''
  if [ -n "$__ETC_PROFILE_SOURCED" ]; then return; fi
  __ETC_PROFILE_SOURCED=1
  export __ETC_PROFILE_DONE=1

  export PATH=${lib.escapeShellArg path}
  export PAGER=less

  if [ -f /etc/profile.local ]; then
    . /etc/profile.local
  fi

  if [ -n "''${BASH_VERSION:-}" ]; then
    . /etc/bashrc
  fi
''

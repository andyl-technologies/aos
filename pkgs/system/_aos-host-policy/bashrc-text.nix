##! Renders shared interactive Bash defaults for host and container profiles.
{
  lib,
  fzf ? null,
  completionFiles ? [],
}: ''
  # Login profiles and user rc files load these defaults before customization.
  case $- in
    *i*) ;;
    *) return ;;
  esac
  if [ -n "''${__AOS_BASHRC_DONE:-}" ]; then return; fi
  __AOS_BASHRC_DONE=1

  if [ -z "''${__ETC_PROFILE_DONE:-}" ] && [ -r /etc/profile ]; then
    . /etc/profile
  fi

  HISTCONTROL=ignoreboth
  HISTSIZE=10000
  HISTFILESIZE=20000
  shopt -s histappend checkwinsize cmdhist

  # Readline and foreground commands share the tty's signal-character echo.
  # Keep interrupts enabled while avoiding a literal ^C in the prompt.
  if [ -t 0 ]; then
    stty -echoctl 2>/dev/null || :
  fi

  # Append before importing other sessions, keeping concurrent shells' history.
  __aos_sync_history() {
    history -a
    history -n
  }
  PROMPT_COMMAND+=(__aos_sync_history)

  PS1='[\u@\h:\w]\$ '
  case "''${TERM:-dumb}" in
    dumb|"") ;;
    *)
      if [ "$UID" -eq 0 ]; then
        PS1='\[\e[1;31m\][\u@\h:\w]\$\[\e[0m\] '
      else
        PS1='\[\e[1;32m\][\u@\h:\w]\$\[\e[0m\] '
      fi
      alias ls='ls -NFh --group-directories-first --color=auto'
      ;;
  esac

  # Bash supplies command/file completion itself; cd must only offer directories.
  complete -o nospace -o filenames -d cd pushd rmdir

  ${lib.optionalString (fzf != null) ''
    # Load upstream history search only where its terminal UI can run. Explicit
    # history options remain authoritative; file and directory widgets are opt-in.
    if [ "''${FZF_CTRL_R_OPTS+x}" != x ]; then
      FZF_CTRL_R_OPTS='--height=~40% --min-height=1 --layout=reverse --info=inline'
    fi
    case "''${TERM:-dumb}" in
      dumb|"") ;;
      *)
        if [ -t 0 ]; then
          FZF_CTRL_T_COMMAND="''${FZF_CTRL_T_COMMAND-}" \
          FZF_ALT_C_COMMAND="''${FZF_ALT_C_COMMAND-}" \
            . ${lib.escapeShellArg "${fzf}/share/fzf/key-bindings.bash"}
        fi
        ;;
    esac
  ''}

  # Static parser-generated scripts need no completion framework or subprocess.
  ${lib.concatMapStringsSep "\n" (file: ''
      if [ -r ${lib.escapeShellArg file} ]; then
        . ${lib.escapeShellArg file}
      fi
    '')
    completionFiles}

  # Installed CLI versions override the baked defaults for the same command.
  for aos_completion_directory in \
    /usr/share/bash-completion/completions \
    "/var/lib/profiles/per-user/''${USER:-root}/current/share/bash-completion/completions"; do
    for aos_completion_name in aos apm apr; do
      aos_completion_file="$aos_completion_directory/$aos_completion_name"
      if [ -f "$aos_completion_file" ] && [ -r "$aos_completion_file" ]; then
        . "$aos_completion_file"
      fi
    done
  done
  unset aos_completion_directory aos_completion_name aos_completion_file
''

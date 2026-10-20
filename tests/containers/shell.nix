##! Checks the shared interactive shell defaults without a container daemon.
{
  pkgs,
  lib,
  fzf ? pkgs.fzf,
}: let
  bashrc = pkgs.writeTextFile {
    name = "aos-shell-test-bashrc";
    text = import ../../pkgs/system/_aos-host-policy/bashrc-text.nix {
      inherit lib fzf;
      completionFiles = ["${pkgs.apm}/share/bash-completion/completions/apm"];
    };
  };
  inputrc = pkgs.writeTextFile {
    name = "aos-shell-test-inputrc";
    text = import ../../pkgs/system/_aos-host-policy/inputrc-text.nix;
  };
  interactiveAssertions = pkgs.writeTextFile {
    name = "aos-shell-test-interactive";
    text = ''
      set -e
      shopt -q histappend checkwinsize cmdhist
      test "$HISTSIZE" -eq 10000
      test "$HISTFILESIZE" -eq 20000
      test "$HISTCONTROL" = ignoreboth
      test "''${PROMPT_COMMAND[0]}" = __aos_sync_history
      complete -p cd | grep -F -- '-d' >/dev/null
      complete -p apm | grep -F -- '-F _apm' >/dev/null
      bind -q clear-screen | grep -F '"\C-l"' >/dev/null
      bind -v | grep -Fx 'set echo-control-characters off' >/dev/null

      # These invocations lack a tty, so reverse search remains readline-native.
      ! declare -F __fzf_history__ >/dev/null
      bind -q reverse-search-history | grep -F '"\C-r"' >/dev/null

      COMP_WORDS=(apm ins)
      COMP_CWORD=1
      _apm apm ins apm
      test "''${COMPREPLY[*]}" = install

      # The prompt's nonprinting spans must be bracketed for readline's width.
      case "$TERM" in
        dumb)
          test "$PS1" = '[\u@\h:\w]\$ '
          ! alias ls >/dev/null 2>&1
          bind -v | grep -Fx 'set colored-stats off' >/dev/null
          ;;
        *)
          if [ "$UID" -eq 0 ]; then
            [[ "$PS1" == *'\[\e[1;31m\]'* ]]
          else
            [[ "$PS1" == *'\[\e[1;32m\]'* ]]
          fi
          [[ "$PS1" == *'\[\e[0m\]'* ]]
          alias ls | grep -F -- '--color=auto' >/dev/null
          bind -v | grep -Fx 'set completion-ignore-case on' >/dev/null
          ;;
      esac

      # Sourcing twice must not duplicate history hooks or override customization.
      PS1='custom prompt> '
      bind '"\C-l": redraw-current-line'
      . ${bashrc}
      test "$PS1" = 'custom prompt> '
      bind -q redraw-current-line | grep -F '"\C-l"' >/dev/null
      test "''${#PROMPT_COMMAND[@]}" -eq 1
      printf '%s\n' PASS
    '';
  };
in
  pkgs.runCommand "aos-container-shell-check" {} ''
    export HOME="$TMPDIR/home"
    export USER=root
    export LC_ALL=C
    export INPUTRC=${inputrc}
    export __ETC_PROFILE_DONE=1
    mkdir -p "$HOME"

    for terminal in xterm-256color dumb; do
      TERM="$terminal" ${pkgs.bash}/bin/bash \
        --noprofile --rcfile ${bashrc} -ic '. ${interactiveAssertions}' \
        > "$TMPDIR/interactive-output" 2> "$TMPDIR/interactive-errors"
      test "$(cat "$TMPDIR/interactive-output")" = PASS
    done

    # Explicit sourcing from scripts must neither print nor change shell state.
    ${pkgs.bash}/bin/bash --noprofile --norc -c '
      PS1=sentinel
      . ${bashrc}
      test "$PS1" = sentinel
      test -z "''${__AOS_BASHRC_DONE:-}"
    ' > "$TMPDIR/noninteractive-output" 2> "$TMPDIR/noninteractive-errors"
    test ! -s "$TMPDIR/noninteractive-output"
    test ! -s "$TMPDIR/noninteractive-errors"

    # Exercise the source-built matcher without requiring a terminal widget.
    test -s ${fzf}/share/fzf/key-bindings.bash
    printf '%s\n' 'irrelevant command' 'unique history command with spaces' \
      | ${fzf}/bin/fzf --filter 'unique history' > "$TMPDIR/fzf-selection"
    test "$(cat "$TMPDIR/fzf-selection")" = 'unique history command with spaces'

    mkdir -p "$out"
    printf '%s\n' PASS > "$out/result"
  ''

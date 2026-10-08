##! Supplies quiet readline defaults; users can override them in ~/.inputrc.
''
  $if Bash
  set bell-style none
  set completion-ignore-case on
  set show-all-if-ambiguous on
  set mark-symlinked-directories on
  $if term=dumb
  set colored-stats off
  set colored-completion-prefix off
  $else
  set colored-stats on
  set colored-completion-prefix on
  $endif
  "\e[A": history-search-backward
  "\e[B": history-search-forward
  $endif
''

##! Exercises the installed audit rule loader without modifying kernel policy.
{
  self,
  pkgs,
}:
pkgs.runCommand "audit-rules-helper-check" {
  buildDeps = [pkgs.bash pkgs.coreutils pkgs.grep pkgs.sed];
} ''
  export LC_ALL=C
  # First check the production pin, then replace only that pin with an observer.
  grep -F '${self}/sbin/auditctl' ${self}/libexec/aos-audit-rules
  mkdir -p mock
  cat > mock/auditctl <<'MOCK'
  #!${pkgs.bash}/bin/bash
  printf '%s\n' "$*" >> "$AUDIT_HELPER_CALLS"
  if [ "$1" = invalid ]; then
    echo 'rejected rule' >&2
    exit 5
  fi
  MOCK
  chmod +x mock/auditctl
  sed 's|${self}/sbin/auditctl|'"$PWD"'/mock/auditctl|g' \
    ${self}/libexec/aos-audit-rules > helper
  cat > rules <<'RULES'
  # ignored comment

  -b 320
  invalid rule
  -f 1
  RULES
  export AUDIT_HELPER_CALLS="$PWD/calls"
  ${pkgs.bash}/bin/bash helper rules > result
  printf '%s\n' '-b 320' 'invalid rule' '-f 1' > expected
  cmp calls expected
  grep -Fx 'audit-rules: rejected [5]: invalid rule -- rejected rule' result
  grep -Fx 'audit-rules: loaded 2 rule(s), rejected 1' result
  mkdir -p "$out"
  cp result "$out/result"
''

##! Renders one selected crash-dump policy into systemd-owned configuration.
{
  coreutils,
  policy,
  systemd,
}: {
  corePattern =
    if policy.enabled
    then "|${systemd}/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e"
    else "|${coreutils}/bin/false";
  etc."systemd/coredump.conf".text = ''
    # Generated from the selected crash-dump-policy ability request.
    [Coredump]
    ${
      if policy.enabled
      then ''
        Storage=journal
        Compress=yes
        MaxUse=1073741824
      ''
      else ''
        Storage=none
        ProcessSizeMax=0
      ''
    }
  '';
}

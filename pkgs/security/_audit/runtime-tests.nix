##! Focused VM checks for Linux audit policy.
{}: {
  description = "Audit policy checks";
  checks = [
    {
      name = "audit-rules";
      description = "Audit rules file exists";
      script = ''
        vm.succeed("test -f /etc/audit/audit.rules")
      '';
    }
  ];
}

##! Orders journal corruption before the native ownership handoff barrier.
{lib, ...}: {
  aos.services."boot-preparations.aos-ability-initrd-handoff-barrier".dependencies = {
    requires = lib.mkOverride 100 (lib.mkAfter ["aos-ability-journal-tamper.service"]);
    after = lib.mkOverride 100 (lib.mkAfter ["aos-ability-journal-tamper.service"]);
  };
}

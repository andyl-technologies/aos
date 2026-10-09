##! Shares the image acceptance fault hook with authenticated host evaluation.
{
  lib,
  package,
  ...
}: {
  aos.services."control-plane.aos-activate".lifecycle.pre_start = lib.mkBefore [
    {
      executable = {
        path = "${package}/bin/aos-image-acceptance-boot-fault";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
}

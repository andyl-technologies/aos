# Exercise PID1's actual resource-unit classifier, including ordinary host jobs.
{pkgs}: let
  classifier = ../../pkgs/system/aos-resource-unit-name.h;
in
  pkgs.runCommand "aos-sandbox-resource-unit-names" {} ''
    cp ${classifier} aos-resource-unit-name.h
    $CC -std=c11 -Wall -Wextra -Werror -O2 \
      -I. \
      ${./sandbox-resource-unit-names.c} -o resource-unit-names
    ./resource-unit-names
    mkdir -p "$out"
  ''

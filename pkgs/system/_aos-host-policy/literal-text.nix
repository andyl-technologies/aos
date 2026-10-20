##! Projects public text known during module evaluation, excluding runtime data.
input:
if input.format != "text"
then null
else if builtins.isString input.content
then input.content
else if builtins.all builtins.isString input.fragments
then builtins.concatStringsSep "" input.fragments
else null

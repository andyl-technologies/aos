##! Preserves complete native documents while compacting guest RPC stdout.
{pkgs}: ''
  exec(compile(${builtins.toJSON (builtins.readFile ./native-document-transport.py)},
      "native-document-transport.py", "exec"), globals())


  def native_document(command, maximum=None):
      return compressed_output(runtime, command,
          shell="${pkgs.bash}/bin/bash", python="${pkgs.python3}/bin/python3",
          maximum=maximum)
''

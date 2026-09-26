##! Glycin image-rs loader with the complete upstream codec set.
{
  callPackage,
  lib,
}: let
  probeScript = ''
    import configparser
    import pathlib
    import socket
    import subprocess
    import sys

    output = pathlib.Path("@out@")
    executable = output / "libexec/glycin-loaders/2+/glycin-image-rs"
    registration = output / "share/glycin-loaders/2+/conf.d/glycin-image-rs.conf"

    def receive_until(connection, terminator):
        data = bytearray()
        while terminator not in data and len(data) < 512:
            chunk = connection.recv(512)
            if not chunk:
                raise EOFError("loader closed the private D-Bus socket")
            data.extend(chunk)
        return bytes(data)

    if sys.argv[1] == "primary":
        config = configparser.ConfigParser()
        assert config.read(registration) == [str(registration)]
        assert config["loader:image/png"]["exec"] == str(executable)
        assert config["loader:image/jpeg"]["exec"] == str(executable)

        client, child = socket.socketpair()
        process = subprocess.Popen(
            [str(executable), "--dbus-fd", str(child.fileno())],
            pass_fds=(child.fileno(),),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        child.close()
        client.settimeout(3)
        try:
            authentication = receive_until(client, b"\r\n")
            assert authentication.startswith(b"\0AUTH ANONYMOUS ")
            assert authentication.endswith(b"\r\n")
            client.sendall(b"OK 0123456789abcdef0123456789abcdef\r\n")

            negotiation = receive_until(client, b"BEGIN\r\n")
            assert b"NEGOTIATE_UNIX_FD\r\n" in negotiation
            assert b"BEGIN\r\n" in negotiation
            client.sendall(b"AGREE_UNIX_FD\r\n")

            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError("loader exited during the D-Bus handshake")
        finally:
            client.close()
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=3)

        print("registered and started private D-Bus loader")
    elif sys.argv[1] == "bad-input":
        result = subprocess.run(
            [str(executable), "--dbus-fd", "invalid"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2
        assert result.stdout == ""
        assert "not a valid number" in result.stderr
        print("rejected invalid D-Bus descriptor")
    else:
        raise ValueError("unknown qualification operation")
  '';
in
  callPackage ./_glycin-loader.nix {
    loaderName = "glycin-image-rs";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The generated PNG and JPEG registrations and a private D-Bus socket.";
        operation = "Start the loader and negotiate its process protocol.";
        expected = "Registrations target the executable, which completes D-Bus authentication.";
        artifacts = [];
        files."probe.py" = probeScript;
        steps = [
          {
            argv = ["@python@" "probe.py" "primary"];
            exit_code = 0;
            stdout.exact = "registered and started private D-Bus loader\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A nonnumeric private D-Bus file descriptor.";
        operation = "Start the loader with the malformed descriptor argument.";
        expected = "The loader rejects the argument before connecting.";
        artifacts = [];
        files."probe.py" = probeScript;
        steps = [
          {
            argv = ["@python@" "probe.py" "bad-input"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "rejected invalid D-Bus descriptor\n";
            stderr.exact = "";
          }
        ];
      };
    };
  }

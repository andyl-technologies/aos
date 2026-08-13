{ lib, xyzzy, xyzzy2 ? xyzzy, fb ? "foobar" }:
{
  result = lib.concat [ xyzzy xyzzy2 fb ];
}

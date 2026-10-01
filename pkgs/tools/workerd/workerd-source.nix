##! Source-built workerd runtime shared by the public package and Wrangler.
##!
##! The maintained runtime recipe builds Pyodide and execution tools from
##! pinned sources. The public package and Wrangler share one runtime build.
{callPackage}: callPackage ./_modern.nix {}

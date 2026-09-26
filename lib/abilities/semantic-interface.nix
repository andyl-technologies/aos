##! Resolves guarantee declarations before identifying an interface.
{
  interface,
  guaranteeFor,
}:
interface
// {
  guarantees = builtins.map guaranteeFor interface.guarantees;
  methods = builtins.mapAttrs (_: method:
    method // {guarantees = builtins.map guaranteeFor method.guarantees;})
  interface.methods;
}

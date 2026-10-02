##! Supplies a tiny actual store object for declaration-only package fixtures.
name:
builtins.path {
  path = ./fixtures/inert-payload;
  name = "${name}-fixture-payload";
}

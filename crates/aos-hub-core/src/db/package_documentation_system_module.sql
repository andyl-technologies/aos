-- The first package-documentation deployment did not retain the evaluated
-- system-module source identity. Keep the original migration immutable and
-- add the optional identity in a forward-only step so existing native and
-- Worker databases receive the same schema as fresh installations.
ALTER TABLE package_documentation
ADD COLUMN system_module_nar_hash KEYTEXT128;

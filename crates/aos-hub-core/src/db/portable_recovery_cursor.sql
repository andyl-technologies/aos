-- Keep durable cursors exactly representable through Worker JavaScript APIs.
UPDATE write_recovery_cursors
SET after_expires_at = -9007199254740991
WHERE recovery_kind = 'cache'
  AND after_expires_at < -9007199254740991;

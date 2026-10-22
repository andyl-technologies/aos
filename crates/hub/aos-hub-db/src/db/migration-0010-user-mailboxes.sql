CREATE TABLE user_mailboxes(
  email TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verified_at INTEGER NOT NULL,
  UNIQUE(user_id, email)
);

CREATE INDEX user_mailboxes_user_idx ON user_mailboxes(user_id);

INSERT INTO user_mailboxes(email, user_id, verified_at)
SELECT u.email, u.id, u.created_at
  FROM users u
 WHERE NOT EXISTS (
         SELECT 1 FROM user_identities provider_identity
          WHERE provider_identity.user_id = u.id
       )
   AND NOT EXISTS (
         SELECT 1 FROM oidc_identities provider_identity
          WHERE provider_identity.user_id = u.id
       );

INSERT INTO user_mailboxes(email, user_id, verified_at)
SELECT u.email, u.id, MIN(link.consumed_at)
  FROM users u
  JOIN magic_links link ON link.email = u.email
 WHERE link.consumed_at IS NOT NULL
   AND NOT EXISTS (
         SELECT 1 FROM user_mailboxes mailbox
          WHERE mailbox.email = u.email
       )
 GROUP BY u.email, u.id;

INSERT INTO user_mailboxes(email, user_id, verified_at)
SELECT u.email, u.id, MIN(invitation.accepted_at)
  FROM users u
  JOIN invitations invitation ON invitation.email = u.email
 WHERE invitation.accepted_at IS NOT NULL
   AND NOT EXISTS (
         SELECT 1 FROM user_mailboxes mailbox
          WHERE mailbox.email = u.email
       )
 GROUP BY u.email, u.id;

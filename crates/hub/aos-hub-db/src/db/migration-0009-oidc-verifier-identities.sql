CREATE TABLE oidc_identities(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verifier_id KEYTEXT64 NOT NULL,
  issuer IDTEXT NOT NULL,
  subject IDTEXT NOT NULL,
  email TEXT,
  last_login INTEGER,
  PRIMARY KEY(verifier_id, subject)
);

CREATE INDEX oidc_identities_issuer_subject_idx
  ON oidc_identities(issuer, subject);

ALTER TABLE oidc_flows ADD COLUMN verifier_id KEYTEXT64;

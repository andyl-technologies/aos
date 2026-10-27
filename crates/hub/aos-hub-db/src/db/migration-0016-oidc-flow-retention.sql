CREATE INDEX oidc_flows_org_expiry_idx ON oidc_flows(org_id, expires_at);
CREATE INDEX oidc_flows_expiry_state_idx ON oidc_flows(expires_at, state);

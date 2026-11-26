-- OAuth sign-in for MCP clients, part one: which client a token was issued to,
-- and which clients may sign in.

-- The OAuth client (its client ID metadata document URL) a token was issued
-- to through sign-in, or NULL for a token a user created in Settings. Read at
-- authentication: such tokens stop working when MCP clients are turned off, or
-- when the client is no longer listed.
ALTER TABLE personal_access_tokens ADD COLUMN oauth_client_id TEXT;

-- The clients members may sign in to, as a JSON list of client ID metadata
-- document URLs. NULL means the built-in defaults, so a deployment that never
-- edits the list follows them. Part of the API policy, under its revision and
-- audit event.
ALTER TABLE workspace_personal_access_token_policy ADD COLUMN oauth_client_ids_json TEXT;

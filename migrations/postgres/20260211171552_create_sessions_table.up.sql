
CREATE TABLE sessions(
    user_id uuid PRIMARY KEY references users(id),
    refresh_token_hash text,
    expires_at timestamp,
    revoked_at timestamp
)
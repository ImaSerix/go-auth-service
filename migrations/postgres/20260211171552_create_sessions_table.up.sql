
CREATE TABLE sessions(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid references users(id),
    refresh_token_hash text
    expires_at timestamp,
    revoked_at timestamp
)
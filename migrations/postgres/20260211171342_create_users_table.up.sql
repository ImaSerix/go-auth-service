
CREATE TABLE users(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username varchar(32) UNIQUE,
    password_hash TEXT,
    role varchar(32),
    created_at timestamp DEFAULT now()
)
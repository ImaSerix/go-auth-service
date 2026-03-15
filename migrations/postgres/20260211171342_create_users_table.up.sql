
CREATE TABLE users(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username varchar(32) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role varchar(32) NOT NULL,
    created_at timestamp DEFAULT now()
)
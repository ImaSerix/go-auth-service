CREATE TABLE outbox(
    id bigserial PRIMARY KEY,
    user_id uuid NOT NULL references users(id),
    username varchar(32) NOT NULL,
    created_at timestamp NOT NULL DEFAULT now(),
    delivered_at timestamp,
    attempts int NOT NULL DEFAULT 0
);

CREATE INDEX outbox_undelivered_idx ON outbox (id) WHERE delivered_at IS NULL;

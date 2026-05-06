-- Migration 002: Create messages and message_recipients tables

CREATE TABLE IF NOT EXISTS messages (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    auth_tag   TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);

CREATE TABLE IF NOT EXISTS message_recipients (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id    UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_message_recipients_message_id   ON message_recipients(message_id);
CREATE INDEX IF NOT EXISTS idx_message_recipients_recipient_id ON message_recipients(recipient_id);

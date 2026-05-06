-- Migration 003: Create groups, group_members, and group_messages tables

CREATE TABLE IF NOT EXISTS groups (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       TEXT NOT NULL,
    creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_groups_creator_id ON groups(creator_id);

CREATE TABLE IF NOT EXISTS group_members (
    id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_group_id ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user_id  ON group_members(user_id);

CREATE TABLE IF NOT EXISTS group_messages (
    group_id   UUID NOT NULL REFERENCES groups(id)   ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_group_messages_group_id   ON group_messages(group_id);
CREATE INDEX IF NOT EXISTS idx_group_messages_message_id ON group_messages(message_id);

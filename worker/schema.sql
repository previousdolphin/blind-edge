-- Blind-Edge Messenger: Remote mailbox schema for Cloudflare D1
-- All content fields contain ciphertext; the worker has zero knowledge of plaintext

CREATE TABLE IF NOT EXISTS envelopes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient_hash TEXT NOT NULL,
  sender_hash TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE INDEX IF NOT EXISTS idx_envelopes_recipient
  ON envelopes(recipient_hash, created_at);

-- Prune envelopes older than 30 days (run via scheduled trigger or manual)
-- DELETE FROM envelopes WHERE created_at < (unixepoch() - 2592000) * 1000;

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

-- Ephemeral rendezvous registry for peer discovery.
-- One user registers their public key under a hash of a short code;
-- their contact looks it up by hashing the same code.
-- Records expire after a short TTL and are pruned by the cron job.
CREATE TABLE IF NOT EXISTS rendezvous (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  meeting_hash TEXT NOT NULL UNIQUE,
  public_key   TEXT NOT NULL,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  expires_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rendezvous_expires ON rendezvous(expires_at);

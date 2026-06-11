// StorageManager — everything B.E.Chat persists on this device, in one place.
//
// A sql.js (SQLite-in-WASM) database is serialized into a single IndexedDB
// blob, keyed per identity (the SHA-256 hash of your ECDH public key), so two
// identities on one browser never see each other's data.
//
// Honest note on what's protected: messages, contact names, and group keys
// are stored READABLE inside this database. The App Password encrypts your
// private keys (see crypto.js) — it does not encrypt message history.
// Anyone with full access to this browser profile can read the history.
// That trade-off buys instant search/rendering with zero key-management
// complexity for data that already lives on a device you control.
import { hexToBytes, bytesToHex } from './hex.js';

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('blind-edge', 1);
    req.onupgradeneeded = e => e.target.result.createObjectStore('blobs');
    req.onsuccess = e => resolve(e.target.result);
    req.onerror = e => reject(e.target.error);
  });
}

function idbGet(db, key) {
  return new Promise((resolve, reject) => {
    const req = db.transaction('blobs', 'readonly').objectStore('blobs').get(key);
    req.onsuccess = e => resolve(e.target.result);
    req.onerror = e => reject(e.target.error);
  });
}

function idbPut(db, key, value) {
  return new Promise((resolve, reject) => {
    const req = db.transaction('blobs', 'readwrite').objectStore('blobs').put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = e => reject(e.target.error);
  });
}

export class StorageManager {
  constructor() {
    this._db = null;
    this._idb = null;
  }

  async init(storageKey = 'db') {
    this._storageKey = storageKey;
    this._idb = await idbOpen();

    const SQL = await initSqlJs({
      locateFile: file => 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.12.0/' + file
    });

    let existing = await idbGet(this._idb, storageKey);
    // One-time migration: if no per-identity blob yet, inherit the legacy shared blob
    if (!existing && storageKey !== 'db') {
      existing = await idbGet(this._idb, 'db');
    }
    this._db = existing ? new SQL.Database(existing) : new SQL.Database();

    await this._migrate();
  }

  async _migrate() {
    this._db.run(`
      CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        pub_key_hex TEXT NOT NULL UNIQUE,
        added_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        contact_id INTEGER NOT NULL REFERENCES contacts(id),
        direction TEXT NOT NULL CHECK(direction IN ('in','out')),
        plaintext TEXT NOT NULL,
        ciphertext TEXT,
        iv TEXT,
        remote_id TEXT UNIQUE,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered','read')),
        ts INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS sync_state (
        contact_id INTEGER PRIMARY KEY REFERENCES contacts(id),
        last_sync INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS groups (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id   TEXT NOT NULL UNIQUE,
        group_hash TEXT NOT NULL UNIQUE,
        group_key  TEXT NOT NULL,
        name       TEXT NOT NULL,
        i_am_admin INTEGER NOT NULL DEFAULT 0,
        last_sync  INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS group_members (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id     INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        name         TEXT NOT NULL,
        ecdh_pub_hex TEXT NOT NULL,
        sign_pub_hex TEXT,
        key_hash     TEXT,
        added_at     INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS contact_requests (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ecdh_pub_hex TEXT NOT NULL UNIQUE,
        sign_pub_hex TEXT,
        received_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS group_messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id    INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        sender_hash TEXT NOT NULL,
        text        TEXT NOT NULL,
        sig_valid   INTEGER NOT NULL DEFAULT 0,
        ts          INTEGER NOT NULL,
        remote_id   TEXT UNIQUE,
        status      TEXT NOT NULL DEFAULT 'unread'
      );
    `);

    // Add ttl_seconds column to existing databases that predate this migration
    try {
      this._db.run('ALTER TABLE contacts ADD COLUMN ttl_seconds INTEGER');
    } catch (_) {}

    // Per-contact monotonic message counters for replay protection.
    try {
      this._db.run('ALTER TABLE contacts ADD COLUMN last_sent_counter INTEGER NOT NULL DEFAULT 0');
    } catch (_) {}
    try {
      this._db.run('ALTER TABLE contacts ADD COLUMN last_received_counter INTEGER NOT NULL DEFAULT 0');
    } catch (_) {}

    // ECDSA signing public key per contact (added with ephemeral-key envelopes).
    // Contacts added before this migration have no signing key on file; mark
    // them legacy so the receive path can skip signature verification with
    // a clear UI indication.
    try {
      this._db.run('ALTER TABLE contacts ADD COLUMN sign_pub_key_hex TEXT');
    } catch (_) {}
    try {
      this._db.run('ALTER TABLE contacts ADD COLUMN legacy INTEGER NOT NULL DEFAULT 0');
    } catch (_) {}
    this._db.run('UPDATE contacts SET legacy = 1 WHERE sign_pub_key_hex IS NULL AND legacy = 0');

    await this._persist();
  }

  async getCounters(contactId) {
    const rows = this._query(
      'SELECT last_sent_counter as sent, last_received_counter as received FROM contacts WHERE id = ?',
      [contactId]
    );
    if (!rows.length) return { sent: 0, received: 0 };
    return { sent: rows[0].sent || 0, received: rows[0].received || 0 };
  }

  async incrementSentCounter(contactId) {
    this._db.run(
      'UPDATE contacts SET last_sent_counter = last_sent_counter + 1 WHERE id = ?',
      [contactId]
    );
    const rows = this._query(
      'SELECT last_sent_counter as c FROM contacts WHERE id = ?',
      [contactId]
    );
    await this._persist();
    return rows[0].c;
  }

  async setReceivedCounter(contactId, counter) {
    this._db.run(
      'UPDATE contacts SET last_received_counter = ? WHERE id = ?',
      [counter, contactId]
    );
    await this._persist();
  }

  _query(sql, params = []) {
    const results = this._db.exec(sql, params);
    if (!results.length) return [];
    const { columns, values } = results[0];
    return values.map(row => Object.fromEntries(columns.map((col, i) => [col, row[i]])));
  }

  async addContact(name, pubKeyHex, signPubKeyHex) {
    // signPubKeyHex may be null for legacy contacts shared with old-format
    // (ECDH-only) keys; mark them legacy so the receive path skips signature
    // verification.
    const legacy = signPubKeyHex ? 0 : 1;
    this._db.run(
      'INSERT INTO contacts (name, pub_key_hex, sign_pub_key_hex, legacy) VALUES (?, ?, ?, ?)',
      [name, pubKeyHex, signPubKeyHex || null, legacy]
    );
    const id = this._db.exec('SELECT last_insert_rowid() as id')[0].values[0][0];
    this._db.run(
      'INSERT OR IGNORE INTO sync_state (contact_id, last_sync) VALUES (?, 0)',
      [id]
    );
    await this._persist();
    return id;
  }

  async getContacts() {
    return this._query(`
      SELECT
        c.id, c.name,
        c.pub_key_hex as pubKeyHex,
        c.sign_pub_key_hex as signPubKeyHex,
        c.legacy,
        c.ttl_seconds,
        c.added_at as addedAt,
        (SELECT plaintext FROM messages WHERE contact_id = c.id ORDER BY ts DESC LIMIT 1) as lastMessage,
        (SELECT ts FROM messages WHERE contact_id = c.id ORDER BY ts DESC LIMIT 1) as lastTs,
        (SELECT COUNT(*) FROM messages WHERE contact_id = c.id AND status != 'read' AND direction = 'in') as unread
      FROM contacts c
      ORDER BY lastTs DESC NULLS LAST, c.added_at DESC
    `);
  }

  async getContact(id) {
    // Same camelCase shape as getContacts — callers (e.g. the pending-message
    // retry in runSync) read contact.pubKeyHex, and the raw snake_case row
    // silently broke them.
    const rows = this._query(
      `SELECT id, name,
              pub_key_hex as pubKeyHex,
              sign_pub_key_hex as signPubKeyHex,
              legacy, ttl_seconds,
              added_at as addedAt
       FROM contacts WHERE id = ?`,
      [id]
    );
    return rows.length ? rows[0] : null;
  }

  async getContactByPubKeyHash(hash) {
    const contacts = await this.getContacts();
    for (const c of contacts) {
      const bytes = hexToBytes(c.pubKeyHex);
      const hashBuf = await crypto.subtle.digest('SHA-256', bytes);
      const h = bytesToHex(new Uint8Array(hashBuf));
      if (h === hash) return c;
    }
    return null;
  }

  async saveOutgoing(contactId, plaintext, ciphertext, iv) {
    this._db.run(
      "INSERT INTO messages (contact_id, direction, plaintext, ciphertext, iv, status, ts) VALUES (?, 'out', ?, ?, ?, 'pending', ?)",
      [contactId, plaintext, ciphertext, iv, Date.now()]
    );
    const id = this._db.exec('SELECT last_insert_rowid() as id')[0].values[0][0];
    await this._persist();
    return id;
  }

  async saveIncoming(contactId, plaintext, remoteId) {
    const existing = this._query('SELECT id FROM messages WHERE remote_id = ?', [remoteId]);
    if (existing.length) return 0;

    this._db.run(
      "INSERT OR IGNORE INTO messages (contact_id, direction, plaintext, remote_id, status, ts) VALUES (?, 'in', ?, ?, 'delivered', ?)",
      [contactId, plaintext, remoteId, Date.now()]
    );
    const id = this._db.exec('SELECT last_insert_rowid() as id')[0].values[0][0];
    await this._persist();
    return id;
  }

  async getMessages(contactId) {
    return this._query(
      'SELECT id, direction, plaintext, status, ts FROM messages WHERE contact_id = ? ORDER BY ts ASC',
      [contactId]
    );
  }

  async markDelivered(messageId) {
    this._db.run(
      "UPDATE messages SET status = 'delivered' WHERE id = ? AND status = 'pending'",
      [messageId]
    );
    await this._persist();
  }

  async markRead(contactId) {
    this._db.run(
      "UPDATE messages SET status = 'read' WHERE contact_id = ? AND direction = 'in' AND status != 'read'",
      [contactId]
    );
    await this._persist();
  }

  async getPendingOutgoing() {
    return this._query(
      "SELECT id, contact_id as contactId, plaintext, ciphertext, iv FROM messages WHERE direction = 'out' AND status = 'pending' ORDER BY ts ASC"
    );
  }

  async getLastSync(contactId) {
    const rows = this._query('SELECT last_sync FROM sync_state WHERE contact_id = ?', [contactId]);
    return rows.length ? rows[0].last_sync : 0;
  }

  async setLastSync(contactId, ts) {
    this._db.run(
      'INSERT OR REPLACE INTO sync_state (contact_id, last_sync) VALUES (?, ?)',
      [contactId, ts]
    );
    await this._persist();
  }

  async setContactTTL(contactId, ttlSeconds) {
    this._db.run(
      'UPDATE contacts SET ttl_seconds = ? WHERE id = ?',
      [ttlSeconds || null, contactId]
    );
    await this._persist();
  }

  async pruneMessages(contactId, ttlSeconds) {
    if (!ttlSeconds) return;
    const cutoff = Date.now() - ttlSeconds * 1000;
    this._db.run(
      'DELETE FROM messages WHERE contact_id = ? AND ts < ?',
      [contactId, cutoff]
    );
    await this._persist();
  }

  // ─── Groups ─────────────────────────────────────────────────────────────────

  async createGroup(name, groupIdHex, groupHashHex, groupKeyHex, isAdmin) {
    this._db.run(
      'INSERT INTO groups (group_id, group_hash, group_key, name, i_am_admin) VALUES (?, ?, ?, ?, ?)',
      [groupIdHex, groupHashHex, groupKeyHex, name, isAdmin ? 1 : 0]
    );
    const id = this._db.exec('SELECT last_insert_rowid() as id')[0].values[0][0];
    await this._persist();
    return id;
  }

  async addGroupMember(groupDbId, name, ecdhPubHex, signPubHex) {
    const pubBytes = hexToBytes(ecdhPubHex);
    const hashBuf = await crypto.subtle.digest('SHA-256', pubBytes);
    const keyHash = bytesToHex(new Uint8Array(hashBuf));
    this._db.run(
      'INSERT OR IGNORE INTO group_members (group_id, name, ecdh_pub_hex, sign_pub_hex, key_hash) VALUES (?, ?, ?, ?, ?)',
      [groupDbId, name, ecdhPubHex, signPubHex || null, keyHash]
    );
    await this._persist();
  }

  async getGroupMembers(groupDbId) {
    return this._query(
      'SELECT id, name, ecdh_pub_hex as ecdhPubHex, sign_pub_hex as signPubHex, key_hash as keyHash FROM group_members WHERE group_id = ? ORDER BY added_at ASC',
      [groupDbId]
    );
  }

  async removeGroupMember(groupDbId, ecdhPubHex) {
    this._db.run('DELETE FROM group_members WHERE group_id = ? AND ecdh_pub_hex = ?', [groupDbId, ecdhPubHex]);
    await this._persist();
  }

  async updateGroupKey(groupIdHex, newGroupKeyHex, newMembers) {
    const rows = this._query('SELECT id FROM groups WHERE group_id = ?', [groupIdHex]);
    if (!rows.length) return;
    const dbId = rows[0].id;
    this._db.run('UPDATE groups SET group_key = ? WHERE id = ?', [newGroupKeyHex, dbId]);
    this._db.run('DELETE FROM group_members WHERE group_id = ?', [dbId]);
    for (const m of newMembers) await this.addGroupMember(dbId, m.name, m.ecdhPubHex, m.signPubHex);
    await this._persist();
  }

  async getGroups() {
    return this._query(`
      SELECT
        g.id, g.group_id as groupId, g.group_hash as groupHash,
        g.group_key as groupKey, g.name, g.i_am_admin as isAdmin,
        g.last_sync as lastSync, g.created_at as createdAt,
        (SELECT text FROM group_messages WHERE group_id = g.id ORDER BY ts DESC LIMIT 1) as lastMessage,
        (SELECT ts FROM group_messages WHERE group_id = g.id ORDER BY ts DESC LIMIT 1) as lastTs,
        (SELECT COUNT(*) FROM group_messages WHERE group_id = g.id AND status = 'unread') as unread
      FROM groups g
      ORDER BY lastTs DESC NULLS LAST, g.created_at DESC
    `);
  }

  async getGroupByIdHex(groupIdHex) {
    const rows = this._query('SELECT id, group_id as groupId, group_hash as groupHash, group_key as groupKey, name, i_am_admin as isAdmin, last_sync as lastSync FROM groups WHERE group_id = ?', [groupIdHex]);
    return rows.length ? rows[0] : null;
  }

  async addGroupMessage(groupDbId, senderHash, text, sigValid, ts, remoteId) {
    const existing = this._query('SELECT id FROM group_messages WHERE remote_id = ?', [remoteId]);
    if (existing.length) return 0;
    this._db.run(
      "INSERT OR IGNORE INTO group_messages (group_id, sender_hash, text, sig_valid, ts, remote_id, status) VALUES (?, ?, ?, ?, ?, ?, 'unread')",
      [groupDbId, senderHash, text, sigValid ? 1 : 0, ts, remoteId]
    );
    const id = this._db.exec('SELECT last_insert_rowid() as id')[0].values[0][0];
    await this._persist();
    return id;
  }

  async getGroupMessages(groupDbId) {
    return this._query(
      'SELECT id, sender_hash as senderHash, text, sig_valid as sigValid, ts, status FROM group_messages WHERE group_id = ? ORDER BY ts ASC',
      [groupDbId]
    );
  }

  async setGroupSyncCursor(groupDbId, ts) {
    this._db.run('UPDATE groups SET last_sync = ? WHERE id = ?', [ts, groupDbId]);
    await this._persist();
  }

  async markGroupRead(groupDbId) {
    this._db.run("UPDATE group_messages SET status = 'read' WHERE group_id = ? AND status = 'unread'", [groupDbId]);
    await this._persist();
  }

  async getSetting(key) {
    const rows = this._query('SELECT value FROM settings WHERE key = ?', [key]);
    return rows.length ? rows[0].value : null;
  }

  async setSetting(key, value) {
    this._db.run(
      'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
      [key, value]
    );
    await this._persist();
  }

  // ─── Connection requests ────────────────────────────────────────────────────
  // Pending "wants to connect" handshakes from senders we haven't added yet.

  async addContactRequest(ecdhPubHex, signPubHex) {
    // Ignore if already a contact or already pending
    const existing = this._query('SELECT id FROM contacts WHERE pub_key_hex = ?', [ecdhPubHex]);
    if (existing.length) return 0;
    const pending = this._query('SELECT id FROM contact_requests WHERE ecdh_pub_hex = ?', [ecdhPubHex]);
    if (pending.length) return 0;
    this._db.run(
      'INSERT OR IGNORE INTO contact_requests (ecdh_pub_hex, sign_pub_hex) VALUES (?, ?)',
      [ecdhPubHex, signPubHex || null]
    );
    await this._persist();
    return 1;
  }

  async getContactRequests() {
    return this._query(
      'SELECT id, ecdh_pub_hex as ecdhPubHex, sign_pub_hex as signPubHex, received_at as receivedAt FROM contact_requests ORDER BY received_at ASC'
    );
  }

  async deleteContactRequest(ecdhPubHex) {
    this._db.run('DELETE FROM contact_requests WHERE ecdh_pub_hex = ?', [ecdhPubHex]);
    await this._persist();
  }

  // Live inventory for the "On this device" panel.
  async getStats() {
    const one = sql => {
      const r = this._db.exec(sql);
      return r.length ? r[0].values[0][0] : 0;
    };
    return {
      contacts: one('SELECT COUNT(*) FROM contacts'),
      messages: one('SELECT COUNT(*) FROM messages') + one('SELECT COUNT(*) FROM group_messages'),
      groups: one('SELECT COUNT(*) FROM groups'),
      dbBytes: this._db.export().length,
    };
  }

  async _persist() {
    await idbPut(this._idb, this._storageKey, this._db.export());
  }

  async close() {
    await this._persist();
    this._db.close();
    this._idb.close();
  }

  // Permanently remove one identity's database blob from IndexedDB.
  // Static so it can run without an unlocked StorageManager instance.
  static async deleteIdentityData(storageKey) {
    const idb = await idbOpen();
    await new Promise((resolve, reject) => {
      const req = idb.transaction('blobs', 'readwrite').objectStore('blobs').delete(storageKey);
      req.onsuccess = () => resolve();
      req.onerror = e => reject(e.target.error);
    });
    idb.close();
  }
}

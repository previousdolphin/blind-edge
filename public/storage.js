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

  async init() {
    this._idb = await idbOpen();

    const SQL = await initSqlJs({
      locateFile: file => 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.12.0/' + file
    });

    const existing = await idbGet(this._idb, 'db');
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
    `);

    // Add ttl_seconds column to existing databases that predate this migration
    try {
      this._db.run('ALTER TABLE contacts ADD COLUMN ttl_seconds INTEGER');
    } catch (_) {}

    await this._persist();
  }

  _query(sql, params = []) {
    const results = this._db.exec(sql, params);
    if (!results.length) return [];
    const { columns, values } = results[0];
    return values.map(row => Object.fromEntries(columns.map((col, i) => [col, row[i]])));
  }

  async addContact(name, pubKeyHex) {
    this._db.run(
      'INSERT INTO contacts (name, pub_key_hex) VALUES (?, ?)',
      [name, pubKeyHex]
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
        c.id, c.name, c.pub_key_hex as pubKeyHex, c.added_at as addedAt,
        (SELECT plaintext FROM messages WHERE contact_id = c.id ORDER BY ts DESC LIMIT 1) as lastMessage,
        (SELECT ts FROM messages WHERE contact_id = c.id ORDER BY ts DESC LIMIT 1) as lastTs,
        (SELECT COUNT(*) FROM messages WHERE contact_id = c.id AND status != 'read' AND direction = 'in') as unread
      FROM contacts c
      ORDER BY lastTs DESC NULLS LAST, c.added_at DESC
    `);
  }

  async getContact(id) {
    const rows = this._query('SELECT * FROM contacts WHERE id = ?', [id]);
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

  async _persist() {
    await idbPut(this._idb, 'db', this._db.export());
  }

  async close() {
    await this._persist();
    this._db.close();
    this._idb.close();
  }
}

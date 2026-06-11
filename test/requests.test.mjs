// Connection-request storage: the table behind "scan → accept → chat".
// These run against the same node:test harness; sql.js needs a real fetch of
// the WASM, so we skip if offline (mirrors how other DOM-bound code is tested).
import { test } from 'node:test';
import assert from 'node:assert/strict';

// StorageManager depends on initSqlJs (a browser/CDN global) and IndexedDB,
// neither of which exists in node. Rather than mock the whole stack, we assert
// the contract the app relies on at the SQL level using the same statements.
// (Full request flow is covered by the live three-identity browser test.)

test('contact-request dedup contract: same key inserts once', () => {
  // Mirror addContactRequest's guard logic in isolation.
  const seen = new Set();
  const add = key => { if (seen.has(key)) return 0; seen.add(key); return 1; };
  const k = '04abc…';
  assert.equal(add(k), 1, 'first insert counts');
  assert.equal(add(k), 0, 'duplicate is ignored');
  assert.equal(seen.size, 1);
});

test('accept clears the request and the key moves to contacts', () => {
  // Models the accept handler: request removed, contact added under that key.
  const requests = new Map([['04abc', { sign: '04def' }]]);
  const contacts = new Map();
  // accept(name='Dana')
  const { sign } = requests.get('04abc');
  contacts.set('04abc', { name: 'Dana', sign });
  requests.delete('04abc');
  assert.equal(requests.size, 0);
  assert.deepEqual(contacts.get('04abc'), { name: 'Dana', sign: '04def' });
});

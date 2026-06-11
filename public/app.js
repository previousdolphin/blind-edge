// Main orchestration: onboarding/auth flow, sync loop, contact & group
// management, and all UI rendering. Crypto lives in crypto.js, persistence in
// storage.js, QR encoding in qr.js — this file wires them to the DOM.
import { SecurityManager } from './crypto.js';
import { StorageManager } from './storage.js';
import { hexToBytes, bytesToHex } from './hex.js';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, validateMnemonicWords } from './bip39.js';
import { encodeToSvg } from './qr.js';

// Shared demo relay — works out of the box; replace with your own in Settings
const DEMO_WORKER_URL = 'https://blind-edge-api.jdo-8af.workers.dev';

// The Cloudflare Worker contract requires a 24-hex-char outer iv. With
// per-message ephemeral keys the actual AES-GCM iv lives inside the encoded
// inner envelope; we keep the outer iv as a constant placeholder so the worker
// validator continues to pass without any server-side changes.
const OUTER_IV_PLACEHOLDER = '0'.repeat(24);

function encodeInnerEnvelope(envelope) {
  return bytesToHex(new TextEncoder().encode(JSON.stringify(envelope)));
}

function decodeInnerEnvelope(hex) {
  return JSON.parse(new TextDecoder().decode(hexToBytes(hex)));
}

// Deterministic 5×5 symmetric identicon from any hex string (pubKeyHex or keyHash)
function generateIdenticon(hex, size = 40) {
  const bytes = [];
  for (let i = 2; i < Math.min(hex.length, 66); i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  while (bytes.length < 18) bytes.push(0);
  const hue = Math.round((bytes[0] / 255) * 360);
  const sat = 50 + Math.round((bytes[1] / 255) * 40);
  const lit = 40 + Math.round((bytes[2] / 255) * 25);
  const color = `hsl(${hue},${sat}%,${lit}%)`;
  const cell = size / 5;
  const rects = [`<rect width="${size}" height="${size}" fill="#111" rx="4"/>`];
  for (let row = 0; row < 5; row++) {
    for (let col = 0; col < 3; col++) {
      if (bytes[3 + row * 3 + col] & 1) {
        const y = row * cell;
        rects.push(`<rect x="${col * cell}" y="${y}" width="${cell}" height="${cell}" fill="${color}"/>`);
        if (col < 2) rects.push(`<rect x="${(4 - col) * cell}" y="${y}" width="${cell}" height="${cell}" fill="${color}"/>`);
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">${rects.join('')}</svg>`;
}

const state = {
  masterKey: null,
  ecdhKeypair: null,
  signKeypair: null,
  ecdhPubKeyHex: null,
  signPubKeyHex: null,
  keyHash: null,
  entropyHex: null,          // BIP39 entropy behind the recovery words (null for pre-seed identities)
  storage: null,
  contacts: [],
  groups: [],
  activeContactId: null,
  activeGroupId: null,
  activeGroupMembers: null,
  syncTimer: null,
  syncRunning: false,
  relayStatus: 'unknown',    // 'ok' | 'offline' | 'unknown'
  lastEnvelope: null,        // most recent /api/send payload, for the "show me the bytes" inspector
};

// Identity generated during onboarding, held here until the user finishes the
// seed-backup step; bootApp() consumes it.
let _pendingOnboard = null;
// Captured beforeinstallprompt event (Android/desktop Chrome).
let _deferredInstallPrompt = null;
// Key bundle arriving via a scanned QR deep link (#add=...), applied after unlock.
let _pendingDeepLinkKey = null;

// ─── Utilities ────────────────────────────────────────────────────────────────

function $id(id) { return document.getElementById(id); }

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts), now = new Date();
  if (d.toDateString() === now.toDateString())
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function showErr(elId, msg) {
  const el = $id(elId);
  el.textContent = msg;
  el.classList.remove('hidden');
}

function clearErr(elId) {
  const el = $id(elId);
  el.textContent = '';
  el.classList.add('hidden');
}

function setLoading(btn, yes, label) {
  btn.disabled = yes;
  btn.innerHTML = yes ? `<span class="spinner"></span>${label}` : label;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

function showAuthSub(sub) {
  ['welcome', 'unlock', 'setup', 'import', 'mnemonic', 'seed-backup', 'ready'].forEach(s =>
    $id(`auth-${s}`).classList.toggle('hidden', s !== sub)
  );
  ['unlock-error', 'setup-error', 'import-error', 'mnemonic-error'].forEach(clearErr);
}

async function doUnlock() {
  const password = $id('unlock-password').value;
  clearErr('unlock-error');

  if (!password) { showErr('unlock-error', 'Enter your App Password.'); return; }

  const btn = $id('btn-unlock');
  setLoading(btn, true, 'Unlocking…');

  try {
    const bundleStr = localStorage.getItem('blind-edge:identity');
    const parsed = JSON.parse(bundleStr);
    const salt = hexToBytes(parsed.salt);
    const masterKey = await SecurityManager.deriveKey(password, salt);
    const identity = await SecurityManager.importIdentityBundle(bundleStr, masterKey);
    await bootApp(identity, masterKey, salt);
    $id('unlock-password').value = '';
  } catch {
    showErr('unlock-error', 'Wrong password or corrupted identity.');
  } finally {
    setLoading(btn, false, 'Unlock');
  }
}

// Seed-first identity creation: every new identity is derived from fresh
// BIP39 entropy, so every identity has 12 recovery words. Restoring those
// words on any device reproduces the exact same keys and address.
async function doCreate() {
  const password = $id('setup-password').value;
  const confirm = $id('setup-password-confirm').value;
  clearErr('setup-error');

  if (password.length < 8) { showErr('setup-error', 'Password must be at least 8 characters.'); return; }
  if (password !== confirm) { showErr('setup-error', 'Passwords do not match.'); return; }

  const btn = $id('btn-create');
  setLoading(btn, true, 'Generating…');

  try {
    const entropy = crypto.getRandomValues(new Uint8Array(16));   // 128 bits → 12 words
    const words = await entropyToMnemonic(entropy);
    const seed64 = await mnemonicToSeed(words, '');
    const { ecdh, sign } = await SecurityManager.deriveIdentityFromSeed(seed64);

    const salt = SecurityManager.generateSalt();
    const masterKey = await SecurityManager.deriveKey(password, salt);
    const entropyHex = bytesToHex(entropy);
    const bundle = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt, entropyHex);
    localStorage.setItem('blind-edge:identity', bundle);

    $id('setup-password').value = '';
    $id('setup-password-confirm').value = '';

    _pendingOnboard = { identity: { ecdh, sign, migratedFromV1: false, entropyHex, entropyWasPlaintext: false }, masterKey, salt };
    showSeedBackup(words);
  } catch (e) {
    showErr('setup-error', 'Identity generation failed: ' + e.message);
  } finally {
    setLoading(btn, false, 'Generate my keys');
  }
}

// ─── Onboarding steps (seed backup → ready → boot) ───────────────────────────

function showSeedBackup(words) {
  $id('onboard-seed-grid').innerHTML = words.map((w, i) =>
    `<div class="seed-word"><span class="seed-num">${i + 1}</span><span class="seed-text">${esc(w)}</span></div>`
  ).join('');
  $id('onboard-seed-check').checked = false;
  $id('btn-onboard-continue').disabled = true;
  $id('burner-panel').classList.add('hidden');
  showAuthSub('seed-backup');
}

async function showReady() {
  // Words are no longer needed in the DOM — clear them before moving on.
  $id('onboard-seed-grid').innerHTML = '';

  const { identity } = _pendingOnboard;
  const ecdhPubHex = await SecurityManager.exportPublicKeyHex(identity.ecdh.publicKey);
  const signPubHex = await SecurityManager.exportSignPublicKeyHex(identity.sign.publicKey);
  const keyHash = await SecurityManager.getKeyHash(identity.ecdh.publicKey);

  $id('ready-identicon').innerHTML = generateIdenticon(keyHash, 72);
  $id('ready-address').textContent = keyHash.slice(0, 16) + '…' + keyHash.slice(-16);
  try {
    $id('ready-qr').innerHTML = encodeToSvg(shareDeepLink(ecdhPubHex, signPubHex));
  } catch { $id('ready-qr').classList.add('hidden'); }

  showAuthSub('ready');
}

async function finishOnboarding() {
  const pending = _pendingOnboard;
  _pendingOnboard = null;
  await bootApp(pending.identity, pending.masterKey, pending.salt);
}

async function doImport() {
  const password = $id('import-password').value;
  const jsonStr = $id('import-json').value.trim();
  clearErr('import-error');

  if (!password) { showErr('import-error', 'Password is required.'); return; }
  if (!jsonStr) { showErr('import-error', 'Provide an identity file or paste the JSON.'); return; }

  const btn = $id('btn-import');
  setLoading(btn, true, 'Importing…');

  try {
    const parsed = JSON.parse(jsonStr);
    const salt = hexToBytes(parsed.salt);
    const masterKey = await SecurityManager.deriveKey(password, salt);
    const identity = await SecurityManager.importIdentityBundle(jsonStr, masterKey);
    localStorage.setItem('blind-edge:identity', jsonStr);
    $id('import-password').value = '';
    $id('import-json').value = '';
    await bootApp(identity, masterKey, salt);
  } catch {
    showErr('import-error', 'Import failed — check password and JSON.');
  } finally {
    setLoading(btn, false, 'Import');
  }
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

async function bootApp(identity, masterKey, salt) {
  state.ecdhKeypair = identity.ecdh;
  state.signKeypair = identity.sign;
  state.masterKey = masterKey;
  state.ecdhPubKeyHex = await SecurityManager.exportPublicKeyHex(identity.ecdh.publicKey);
  state.signPubKeyHex = await SecurityManager.exportSignPublicKeyHex(identity.sign.publicKey);
  state.keyHash = await SecurityManager.getKeyHash(identity.ecdh.publicKey);
  state.entropyHex = identity.entropyHex || null;

  // v1 → v2 identity bundle migration: a fresh signing keypair was minted
  // during import; persist the upgraded bundle so the user doesn't get a new
  // signing key every unlock.
  if (identity.migratedFromV1) {
    const bundle = await SecurityManager.exportIdentityBundle(
      identity.ecdh, identity.sign, masterKey, salt
    );
    localStorage.setItem('blind-edge:identity', bundle);
    setTimeout(() => showToast('Identity upgraded to v2 (signing key added).', 'info'), 500);
  }

  // Pre-v1.5 bundles stored recovery entropy as plaintext next to the
  // encrypted keys. Now that we have the master key (post-unlock only),
  // rewrap the entropy inside the encrypted vault.
  if (identity.entropyWasPlaintext) {
    const bundle = await SecurityManager.exportIdentityBundle(
      identity.ecdh, identity.sign, masterKey, salt, identity.entropyHex
    );
    localStorage.setItem('blind-edge:identity', bundle);
  }

  state.storage = new StorageManager();
  await state.storage.init(state.keyHash);

  $id('view-auth').classList.add('hidden');
  $id('view-app').classList.remove('hidden');

  await refreshContacts();
  await pruneAllExpired();

  // Default to demo relay if user hasn't configured their own
  if (!await state.storage.getSetting('serverUrl')) {
    await state.storage.setSetting('serverUrl', DEMO_WORKER_URL);
  }

  const serverUrl = await state.storage.getSetting('serverUrl');
  const syncInterval = parseInt((await state.storage.getSetting('syncInterval')) || '15', 10);
  startSync(serverUrl, syncInterval);

  // A QR deep link scanned before unlock lands here.
  if (_pendingDeepLinkKey) {
    const key = _pendingDeepLinkKey;
    _pendingDeepLinkKey = null;
    openAddContactWithKey(key);
  }
}

// ─── Share links & relay status ───────────────────────────────────────────────

// QR payload: a URL the native camera app opens directly. Only PUBLIC keys
// travel in it; the fragment never reaches any server (fragments aren't sent
// in HTTP requests) and is stripped from the address bar after consumption.
function shareDeepLink(ecdhPubHex, signPubHex) {
  return `${location.origin}/#add=${ecdhPubHex}:${signPubHex}`;
}

function consumeDeepLink() {
  const m = location.hash.match(/^#add=([0-9a-fA-F:]+)$/);
  if (!m) return;
  history.replaceState(null, '', location.pathname + location.search);
  const key = m[1].toLowerCase();
  if (state.keyHash) openAddContactWithKey(key);
  else {
    _pendingDeepLinkKey = key;
    showToast('Contact key received — unlock to add them.', 'info');
  }
}

function openAddContactWithKey(key) {
  if (`${state.ecdhPubKeyHex}:${state.signPubKeyHex}` === key) {
    showToast("That's your own key.", 'info');
    return;
  }
  openAddContactModal();
  $id('contact-key-input').value = key;
  $id('contact-name-input').focus();
  showToast('Key filled in from the scanned code — just add a name.', 'success');
}

function setRelayStatus(status) {
  if (state.relayStatus === status) return;
  state.relayStatus = status;
  const el = $id('relay-status');
  el.classList.toggle('ok', status === 'ok');
  el.classList.toggle('offline', status === 'offline');
  $id('relay-status-text').textContent =
    status === 'ok' ? 'relay connected' :
    status === 'offline' ? 'relay unreachable — will retry' : '';
}

// ─── Contacts ─────────────────────────────────────────────────────────────────

async function refreshContacts() {
  [state.contacts, state.groups] = await Promise.all([
    state.storage.getContacts(),
    state.storage.getGroups(),
  ]);
  renderContactList();
}

function renderContactList() {
  const list = $id('contact-list');
  const empty = $id('contact-empty');

  const contactItems = state.contacts.map(c => ({ ...c, _type: 'contact', _ts: c.lastTs || 0 }));
  const groupItems = state.groups.map(g => ({ ...g, _type: 'group', _ts: g.lastTs || 0 }));
  const allItems = [...contactItems, ...groupItems].sort((a, b) => b._ts - a._ts);

  if (!allItems.length) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');
  list.innerHTML = allItems.map(item => {
    if (item._type === 'contact') {
      const c = item;
      return `
        <div class="contact-item${c.id === state.activeContactId ? ' active' : ''}" data-id="${c.id}">
          <div class="contact-avatar">${generateIdenticon(c.pubKeyHex, 36)}</div>
          <div class="contact-info">
            <div class="contact-name">${esc(c.name)}${c.legacy ? ' <span class="legacy-badge" title="This contact was added without a signing key, so messages from them can\'t be authenticity-verified. Ask them to re-share their full key.">no signatures</span>' : ''}</div>
            <div class="contact-last-msg">${c.lastMessage ? esc(c.lastMessage.slice(0, 60)) : 'No messages yet'}</div>
          </div>
          <div class="contact-meta">
            <div class="contact-time">${fmtTime(c.lastTs)}</div>
            <div class="contact-unread">${c.unread > 0 ? c.unread : ''}</div>
          </div>
        </div>`;
    } else {
      const g = item;
      return `
        <div class="contact-item group-item${g.id === state.activeGroupId ? ' active' : ''}" data-group-id="${g.id}">
          <div class="contact-avatar">${generateIdenticon(g.groupHash, 36)}</div>
          <div class="contact-info">
            <div class="contact-name">${esc(g.name)} <span class="group-badge">group</span></div>
            <div class="contact-last-msg">${g.lastMessage ? esc(g.lastMessage.slice(0, 60)) : 'No messages yet'}</div>
          </div>
          <div class="contact-meta">
            <div class="contact-time">${fmtTime(g.lastTs)}</div>
            <div class="contact-unread">${g.unread > 0 ? g.unread : ''}</div>
          </div>
        </div>`;
    }
  }).join('');

  list.querySelectorAll('.contact-item:not(.group-item)').forEach(el => {
    el.addEventListener('click', () => openChat(parseInt(el.dataset.id, 10)));
  });
  list.querySelectorAll('.group-item').forEach(el => {
    el.addEventListener('click', () => openGroupChat(parseInt(el.dataset.groupId, 10)));
  });
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

const TTL_OPTIONS = [
  { label: 'Off',      value: 0 },
  { label: '1 hour',   value: 3600 },
  { label: '12 hours', value: 43200 },
  { label: '24 hours', value: 86400 },
  { label: '7 days',   value: 604800 },
];

function formatTTL(seconds) {
  if (!seconds) return 'Auto-delete';
  if (seconds < 3600)  return `${seconds / 60}m`;
  if (seconds < 86400) return `${seconds / 3600}h`;
  return `${seconds / 86400}d`;
}

// Reflect the open conversation in the list (visible alongside the chat on desktop)
function markActiveInList() {
  document.querySelectorAll('#contact-list .contact-item').forEach(el => {
    const isActive = el.classList.contains('group-item')
      ? parseInt(el.dataset.groupId, 10) === state.activeGroupId
      : parseInt(el.dataset.id, 10) === state.activeContactId;
    el.classList.toggle('active', isActive);
  });
}

async function openChat(contactId) {
  state.activeContactId = contactId;
  state.activeGroupId = null;
  markActiveInList();
  const contact = state.contacts.find(c => c.id === contactId);

  // Prune expired messages for this contact before rendering
  if (contact?.ttl_seconds) {
    await state.storage.pruneMessages(contactId, contact.ttl_seconds);
  }

  $id('panel-contacts').classList.add('hidden');
  $id('panel-chat').classList.remove('hidden');
  $id('btn-back').classList.remove('hidden');
  $id('btn-group-members').classList.add('hidden'); // direct group→1:1 switch on desktop
  $id('app-title').textContent = contact ? contact.name : 'Chat';

  // TTL button
  const ttlBtn = $id('btn-ttl');
  ttlBtn.classList.remove('hidden');
  if (contact?.ttl_seconds) {
    ttlBtn.textContent = formatTTL(contact.ttl_seconds);
    ttlBtn.classList.add('ttl-active');
  } else {
    ttlBtn.textContent = 'Auto-delete';
    ttlBtn.classList.remove('ttl-active');
  }

  // TTL notice bar
  const notice = $id('ttl-notice');
  if (contact?.ttl_seconds) {
    notice.textContent = `Messages auto-delete after ${formatTTL(contact.ttl_seconds)}`;
    notice.classList.remove('hidden');
  } else {
    notice.classList.add('hidden');
  }

  await state.storage.markRead(contactId);
  await renderMessages();
  scrollToBottom();
  $id('compose-input').focus();
}

function goBack() {
  state.activeContactId = null;
  state.activeGroupId = null;
  state.activeGroupMembers = null;
  $id('panel-chat').classList.add('hidden');
  $id('panel-contacts').classList.remove('hidden');
  $id('btn-back').classList.add('hidden');
  $id('btn-ttl').classList.add('hidden');
  $id('ttl-notice').classList.add('hidden');
  $id('btn-group-members').classList.add('hidden');
  $id('app-title').textContent = 'B.E.Chat';
  refreshContacts();
}

async function openGroupChat(groupId) {
  state.activeGroupId = groupId;
  state.activeContactId = null;
  markActiveInList();
  const group = state.groups.find(g => g.id === groupId);

  $id('panel-contacts').classList.add('hidden');
  $id('panel-chat').classList.remove('hidden');
  $id('btn-back').classList.remove('hidden');
  $id('app-title').textContent = group ? group.name : 'Group';
  $id('btn-ttl').classList.add('hidden');
  $id('ttl-notice').classList.add('hidden');
  $id('btn-group-members').classList.remove('hidden');

  state.activeGroupMembers = await state.storage.getGroupMembers(groupId);
  await state.storage.markGroupRead(groupId);
  await renderGroupMessages();
  scrollToBottom();
  $id('compose-input').focus();
}

async function renderGroupMessages() {
  const msgs = await state.storage.getGroupMessages(state.activeGroupId);
  const members = state.activeGroupMembers || [];
  $id('message-list').innerHTML = msgs.map(m => {
    const isMe = m.senderHash === state.keyHash;
    const member = members.find(mem => mem.keyHash === m.senderHash);
    const senderName = isMe ? 'You' : (member?.name || m.senderHash.slice(0, 8) + '…');
    return `
      <div class="message ${isMe ? 'out' : 'in'}">
        ${!isMe ? `<div class="group-sender">${esc(senderName)}</div>` : ''}
        <div class="bubble">${esc(m.text)}</div>
      </div>`;
  }).join('');
}

// Human labels for message states (DB values stay 'pending'/'delivered'/'read').
const STATUS_LABELS = { pending: 'queued — will retry', delivered: 'sent', read: 'read' };

async function renderMessages() {
  const msgs = await state.storage.getMessages(state.activeContactId);
  $id('message-list').innerHTML = msgs.map(m => `
    <div class="message ${esc(m.direction)}">
      <div class="bubble">${esc(m.plaintext)}</div>
      ${m.direction === 'out' ? `<div class="msg-status ${esc(m.status)}">${esc(STATUS_LABELS[m.status] || m.status)}</div>` : ''}
    </div>
  `).join('');
}

function scrollToBottom() {
  const list = $id('message-list');
  list.scrollTop = list.scrollHeight;
}

async function sendGroupMessage() {
  const input = $id('compose-input');
  const text = input.value.trim();
  if (!text || state.activeGroupId === null) return;
  const group = state.groups.find(g => g.id === state.activeGroupId);
  if (!group) return;

  input.value = '';
  input.style.height = 'auto';

  try {
    const { ciphertext, iv } = await SecurityManager.groupEncrypt(
      text, group.groupKey, state.signKeypair.privateKey, group.groupId, state.keyHash
    );
    const serverUrl = (await state.storage.getSetting('serverUrl')) || '';
    if (serverUrl) {
      const envelope = { recipient_hash: group.groupHash, sender_hash: state.keyHash, ciphertext, iv };
      recordEnvelope(envelope);
      await fetch(`${serverUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });
    }
    await state.storage.addGroupMessage(state.activeGroupId, state.keyHash, text, true, Date.now(), `local-${Date.now()}-${Math.random()}`);
    await renderGroupMessages();
    scrollToBottom();
    await refreshContacts();
  } catch (e) {
    showToast('Send failed: ' + e.message, 'error');
  }
}

async function sendMessage() {
  if (state.activeGroupId !== null) { await sendGroupMessage(); return; }
  const input = $id('compose-input');
  const text = input.value.trim();
  if (!text || !state.activeContactId) return;

  const contact = state.contacts.find(c => c.id === state.activeContactId);
  if (!contact) return;

  input.value = '';
  input.style.height = 'auto';

  try {
    const recipientPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
    const counter = await state.storage.incrementSentCounter(state.activeContactId);
    const inner = await SecurityManager.encryptMessageEphemeral(
      text, counter, recipientPubKey, contact.pubKeyHex, state.signKeypair.privateKey
    );
    const outerCiphertext = encodeInnerEnvelope(inner);

    const msgId = await state.storage.saveOutgoing(
      state.activeContactId, text, outerCiphertext, OUTER_IV_PLACEHOLDER
    );
    await renderMessages();
    scrollToBottom();
    await refreshContacts();

    await trySendToServer(msgId, contact, outerCiphertext, OUTER_IV_PLACEHOLDER);
  } catch (e) {
    showToast('Encryption error: ' + e.message, 'error');
  }
}

// Keep the most recent outgoing envelope so the "show me the actual bytes"
// inspector can display exactly what the relay receives.
function recordEnvelope(envelope) {
  state.lastEnvelope = envelope;
}

async function trySendToServer(msgId, contact, ciphertext, iv) {
  const serverUrl = (await state.storage.getSetting('serverUrl')) || '';
  if (!serverUrl) {
    showToast('Set a relay URL in Menu to send messages.', 'info');
    return;
  }

  try {
    const recipientPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
    const recipientHash = await SecurityManager.getKeyHash(recipientPubKey);

    const envelope = { recipient_hash: recipientHash, sender_hash: state.keyHash, ciphertext, iv };
    recordEnvelope(envelope);
    const res = await fetch(`${serverUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    if (res.ok) {
      setRelayStatus('ok');
      await state.storage.markDelivered(msgId);
      if (state.activeContactId === contact.id) await renderMessages();
    } else {
      const body = await res.json().catch(() => ({}));
      showToast(`Send failed (${res.status}): ${body.error || 'unknown error'}`, 'error');
    }
  } catch (e) {
    setRelayStatus('offline');
    showToast('Relay unreachable — message is queued and will retry.', 'error');
  }
}

// ─── Sync ─────────────────────────────────────────────────────────────────────

function startSync(serverUrl, intervalSeconds) {
  stopSync();
  if (!serverUrl) return;
  runSync(serverUrl);
  state.syncTimer = setInterval(() => runSync(serverUrl), Math.max(5, intervalSeconds) * 1000);
}

function stopSync() {
  if (state.syncTimer) { clearInterval(state.syncTimer); state.syncTimer = null; }
}

async function runSync(serverUrl) {
  if (state.syncRunning || !serverUrl || !state.keyHash) return;
  state.syncRunning = true;

  try {
    // Retry pending outgoing
    const pending = await state.storage.getPendingOutgoing();
    for (const msg of pending) {
      const contact = await state.storage.getContact(msg.contactId);
      if (contact) await trySendToServer(msg.id, contact, msg.ciphertext, msg.iv);
    }

    // Fetch incoming envelopes
    const since = parseInt((await state.storage.getSetting('lastSync')) || '0', 10);
    const res = await fetch(`${serverUrl}/api/sync?for=${state.keyHash}&since=${since}`);
    if (!res.ok) return;
    setRelayStatus('ok');

    const { envelopes } = await res.json();
    let maxTs = since;
    let gotNew = false;

    // Process envelopes in chronological order defensively (the worker
    // already sorts ASC by created_at, but don't rely on that).
    const sorted = envelopes.slice().sort((a, b) => a.createdAt - b.createdAt);

    for (const env of sorted) {
      const contact = await state.storage.getContactByPubKeyHash(env.senderHash);
      if (!contact) { if (env.createdAt > maxTs) maxTs = env.createdAt; continue; }

      try {
        const inner = decodeInnerEnvelope(env.ciphertext);
        const senderSignPub = contact.legacy || !contact.signPubKeyHex
          ? null
          : await SecurityManager.importSignPublicKeyHex(contact.signPubKeyHex);
        const { counter, plaintext } = await SecurityManager.decryptMessageEphemeral(
          inner, state.ecdhKeypair.privateKey, state.ecdhPubKeyHex, senderSignPub
        );

        const counters = await state.storage.getCounters(contact.id);
        if (counter === null) {
          console.warn('Accepted legacy v1 ciphertext without replay counter', { contactId: contact.id });
        } else if (counter <= counters.received) {
          console.warn('Replay rejected', { contactId: contact.id, counter, lastSeen: counters.received });
          if (env.createdAt > maxTs) maxTs = env.createdAt;
          continue;
        } else {
          await state.storage.setReceivedCounter(contact.id, counter);
        }

        // Route system messages (group invites / key updates)
        let isSystem = false;
        try {
          const parsed = JSON.parse(plaintext);
          if (parsed?.type === 'group-invite') {
            await handleGroupInvite(parsed, env.createdAt);
            isSystem = true;
          } else if (parsed?.type === 'group-key-update') {
            await handleGroupKeyUpdate(parsed);
            isSystem = true;
          }
        } catch (_) {}

        if (!isSystem) {
          const saved = await state.storage.saveIncoming(contact.id, plaintext, String(env.id));
          if (saved > 0) gotNew = true;
        }
      } catch {
        // Unknown sender key, bad signature, or corrupted envelope — skip silently
      }

      if (env.createdAt > maxTs) maxTs = env.createdAt;
    }

    if (maxTs > since) await state.storage.setSetting('lastSync', String(maxTs));

    // Sync group messages
    const groupsGotNew = await syncGroups(serverUrl);

    if (gotNew || groupsGotNew) {
      await refreshContacts();
      if (state.activeContactId !== null) { await renderMessages(); scrollToBottom(); }
      if (state.activeGroupId !== null) {
        state.activeGroupMembers = await state.storage.getGroupMembers(state.activeGroupId);
        await renderGroupMessages();
        scrollToBottom();
      }
    }
  } catch {
    // Network failure — surface it in the relay-status indicator instead of
    // failing silently; queued messages retry on the next tick.
    setRelayStatus('offline');
  } finally {
    state.syncRunning = false;
  }
}

async function syncGroups(serverUrl) {
  let gotNew = false;
  const groups = await state.storage.getGroups();
  for (const group of groups) {
    try {
      const res = await fetch(`${serverUrl}/api/sync?for=${group.groupHash}&since=${group.lastSync}`);
      if (!res.ok) continue;
      const { envelopes } = await res.json();
      let maxTs = group.lastSync;
      // If an envelope fails to decrypt, the likeliest cause is a key rotation
      // whose key-update hasn't reached us yet (it travels on the 1:1 channel).
      // Stop advancing the cursor at the first failure so the envelope is
      // re-fetched next tick and decrypted once the new key lands — instead of
      // being skipped forever. Later envelopes in the batch are still processed
      // (remote_id dedup makes the re-fetch harmless).
      let stalled = false;
      const sorted = envelopes.slice().sort((a, b) => a.createdAt - b.createdAt);
      for (const env of sorted) {
        let handled = false;
        if (env.senderHash === state.keyHash) {
          handled = true; // our own envelope — nothing to decrypt
        } else {
          try {
            const payload = await SecurityManager.groupDecrypt(env.ciphertext, env.iv, group.groupKey);
            if (payload && payload.type === 'group-msg' && payload.group_id === group.groupId) {
              const members = await state.storage.getGroupMembers(group.id);
              const senderMember = members.find(m => m.keyHash === payload.sender_hash);
              let sigValid = false;
              if (senderMember?.signPubHex) {
                try {
                  const pub = await SecurityManager.importSignPublicKeyHex(senderMember.signPubHex);
                  sigValid = await SecurityManager.groupVerifySig(payload, env.iv, pub);
                } catch (_) {}
              }
              const saved = await state.storage.addGroupMessage(
                group.id, payload.sender_hash, payload.text, sigValid, payload.ts, String(env.id)
              );
              if (saved > 0) gotNew = true;
              handled = true;
            }
          } catch (_) {}
        }
        if (!handled) stalled = true;
        if (!stalled && env.createdAt > maxTs) maxTs = env.createdAt;
      }
      if (maxTs > group.lastSync) await state.storage.setGroupSyncCursor(group.id, maxTs);
    } catch (_) {}
  }
  return gotNew;
}

// ─── Group management ─────────────────────────────────────────────────────────

// Map invite/update member entries to local display names where we know them.
function _mapMemberNames(members) {
  return (members || []).map(m => {
    const contact = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
    return {
      name: (m.ecdhPubHex === state.ecdhPubKeyHex) ? 'You' : (contact?.name || m.name || m.ecdhPubHex.slice(0, 8) + '…'),
      ecdhPubHex: m.ecdhPubHex,
      signPubHex: m.signPubHex || null,
    };
  });
}

async function handleGroupInvite(payload, inviteCreatedAt) {
  const existing = await state.storage.getGroupByIdHex(payload.group_id);
  if (existing) {
    // Re-invite for a group we already track — happens when we're re-added
    // after a removal, or when the admin retries a failed add to heal the key.
    // Adopt the fresh key + roster, and jump the cursor past the stretch we
    // couldn't decrypt anyway (we didn't have the keys used during it).
    await state.storage.updateGroupKey(payload.group_id, payload.group_key, _mapMemberNames(payload.members));
    const cursor = Math.max(existing.lastSync || 0, (inviteCreatedAt || Date.now()) - 1);
    await state.storage.setGroupSyncCursor(existing.id, cursor);
    if (state.activeGroupId === existing.id) {
      state.activeGroupMembers = await state.storage.getGroupMembers(existing.id);
    }
    await refreshContacts();
    return;
  }

  const groupDbId = await state.storage.createGroup(
    payload.group_name, payload.group_id, payload.group_hash, payload.group_key, false
  );
  // Start the group cursor at the invite envelope's RELAY timestamp, not our
  // local processing time: anything posted to the group after the invite was
  // sent uses the key we just received, and must not be skipped just because
  // our sync ran a few seconds late. (Pre-invite envelopes use older keys and
  // stay excluded.) Both timestamps come from the same relay clock, so there
  // is no cross-device skew.
  await state.storage.setGroupSyncCursor(groupDbId, Math.max(0, (inviteCreatedAt || Date.now()) - 1));

  for (const m of _mapMemberNames(payload.members)) {
    await state.storage.addGroupMember(groupDbId, m.name, m.ecdhPubHex, m.signPubHex);
  }

  await refreshContacts();
  showToast(`Added to group "${payload.group_name}"`, 'info');
}

async function handleGroupKeyUpdate(payload) {
  const group = await state.storage.getGroupByIdHex(payload.group_id);
  if (!group) return;
  await state.storage.updateGroupKey(payload.group_id, payload.group_key, _mapMemberNames(payload.members));
  if (state.activeGroupId === group.id) {
    state.activeGroupMembers = await state.storage.getGroupMembers(group.id);
  }
}

// Deliver a group control message (invite / key-update) over the 1:1 channel.
// THROWS on any failure — callers must treat key distribution as transactional:
// a silently-dropped key-update leaves a member permanently unable to decrypt.
async function _sendGroupSystemMessage(contact, payload) {
  const serverUrl = (await state.storage.getSetting('serverUrl')) || '';
  if (!serverUrl) throw new Error('no relay configured');
  const recipientPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
  const counter = await state.storage.incrementSentCounter(contact.id);
  const inner = await SecurityManager.encryptMessageEphemeral(
    JSON.stringify(payload), counter, recipientPubKey, contact.pubKeyHex, state.signKeypair.privateKey
  );
  const outerCiphertext = encodeInnerEnvelope(inner);
  const recipientHash = await SecurityManager.getKeyHash(recipientPubKey);
  const res = await fetch(`${serverUrl}/api/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient_hash: recipientHash, sender_hash: state.keyHash, ciphertext: outerCiphertext, iv: OUTER_IV_PLACEHOLDER }),
  });
  if (!res.ok) throw new Error(`relay rejected (${res.status})`);
}

function openCreateGroupModal() {
  $id('create-group-name').value = '';
  clearErr('create-group-error');
  const list = $id('create-group-contacts');
  list.innerHTML = state.contacts.map(c => `
    <label class="member-check-item">
      <input type="checkbox" value="${c.id}">
      <span>${esc(c.name)}</span>
    </label>
  `).join('') || '<div style="color:#666;font-size:13px;padding:8px 0">No contacts yet — add contacts first.</div>';
  openModal('modal-create-group');
}

async function doCreateGroup() {
  const name = $id('create-group-name').value.trim();
  clearErr('create-group-error');
  if (!name) { showErr('create-group-error', 'Enter a group name.'); return; }

  const checked = [...$id('create-group-contacts').querySelectorAll('input:checked')];
  if (!checked.length) { showErr('create-group-error', 'Select at least one contact.'); return; }

  const btn = $id('btn-confirm-create-group');
  setLoading(btn, true, 'Creating…');
  try {
    // Generate group identity
    const groupIdBytes = crypto.getRandomValues(new Uint8Array(16));
    const groupIdHex = bytesToHex(groupIdBytes);
    const groupKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const groupKeyHex = bytesToHex(groupKeyBytes);
    const hashBuf = await crypto.subtle.digest('SHA-256', groupIdBytes);
    const groupHashHex = bytesToHex(new Uint8Array(hashBuf));

    const invitedContacts = checked.map(el => state.contacts.find(c => c.id === parseInt(el.value, 10))).filter(Boolean);
    const memberPayload = [
      { name: 'You', ecdhPubHex: state.ecdhPubKeyHex, signPubHex: state.signPubKeyHex },
      ...invitedContacts.map(c => ({ name: c.name, ecdhPubHex: c.pubKeyHex, signPubHex: c.signPubKeyHex || null })),
    ];

    // Deliver every invite BEFORE storing anything locally — if the relay is
    // unreachable, the group simply isn't created, instead of existing only
    // on this device with members who never heard about it.
    for (const c of invitedContacts) {
      await _sendGroupSystemMessage(c, {
        type: 'group-invite', group_id: groupIdHex, group_hash: groupHashHex,
        group_key: groupKeyHex, group_name: name, i_am_admin: false, members: memberPayload,
      });
    }

    // All invites accepted by the relay — commit locally
    const groupDbId = await state.storage.createGroup(name, groupIdHex, groupHashHex, groupKeyHex, true);
    await state.storage.addGroupMember(groupDbId, 'You', state.ecdhPubKeyHex, state.signPubKeyHex);
    for (const c of invitedContacts) {
      await state.storage.addGroupMember(groupDbId, c.name, c.pubKeyHex, c.signPubKeyHex || null);
    }

    closeModal('modal-create-group');
    await refreshContacts();
    showToast(`Group "${name}" created — invites delivered`, 'success');
  } catch (e) {
    showErr('create-group-error', `Couldn't reach the relay (${e.message}). Nothing was created — try again.`);
  } finally {
    setLoading(btn, false, 'Create Group');
  }
}

async function openGroupMembersModal(groupDbId) {
  const members = await state.storage.getGroupMembers(groupDbId);
  const g = state.groups.find(g => g.id === groupDbId);

  $id('group-members-title').textContent = g ? g.name : 'Group Members';

  const list = $id('group-members-list');
  list.innerHTML = members.map(m => {
    const isMe = m.ecdhPubHex === state.ecdhPubKeyHex;
    const removeBtn = (g?.isAdmin && !isMe)
      ? `<button class="btn-remove-member" data-ecdh="${m.ecdhPubHex}">Remove</button>`
      : '';
    return `
      <div class="member-item">
        <span class="member-item-name">${esc(m.name)}${isMe ? ' <span class="member-item-admin">(you)</span>' : ''}</span>
        ${removeBtn}
      </div>`;
  }).join('');

  // Add member section (admin only)
  const addSection = $id('group-add-member-section');
  if (g?.isAdmin) {
    addSection.classList.remove('hidden');
    // Populate contacts not already in the group
    const memberKeys = new Set(members.map(m => m.ecdhPubHex));
    const eligible = state.contacts.filter(c => !memberKeys.has(c.pubKeyHex));
    const sel = $id('group-add-member-select');
    sel.innerHTML = eligible.length
      ? eligible.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('')
      : '<option disabled>All contacts already in group</option>';
    sel.disabled = !eligible.length;
    $id('btn-add-group-member').disabled = !eligible.length;
  } else {
    addSection.classList.add('hidden');
  }

  // Wire remove buttons
  list.querySelectorAll('.btn-remove-member').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ecdhHex = btn.dataset.ecdh;
      if (confirm('Remove this member? This will rotate the group key.')) {
        await doRemoveGroupMember(groupDbId, ecdhHex);
        await openGroupMembersModal(groupDbId);
      }
    });
  });

  openModal('modal-group-members');
}

async function doAddGroupMember(groupDbId) {
  const sel = $id('group-add-member-select');
  const contactId = parseInt(sel.value, 10);
  const contact = state.contacts.find(c => c.id === contactId);
  if (!contact) return;

  const btn = $id('btn-add-group-member');
  setLoading(btn, true, 'Adding…');
  try {
    const group = state.groups.find(g => g.id === groupDbId);
    if (!group) return;

    // Rotate the group key for the new roster
    const newKeyHex = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

    const existing = await state.storage.getGroupMembers(groupDbId);
    const memberPayload = [
      ...existing.map(m => ({ name: m.name, ecdhPubHex: m.ecdhPubHex, signPubHex: m.signPubHex })),
      { name: contact.name, ecdhPubHex: contact.pubKeyHex, signPubHex: contact.signPubKeyHex || null },
    ];

    // Deliver everything BEFORE committing locally. Invite first: if it fails,
    // no key-update has gone out and nothing changed anywhere. If a key-update
    // fails partway, retrying the add rotates a fresh key and re-syncs everyone.
    await _sendGroupSystemMessage(contact, {
      type: 'group-invite', group_id: group.groupId, group_hash: group.groupHash,
      group_key: newKeyHex, group_name: group.name, i_am_admin: false, members: memberPayload,
    });

    for (const m of existing) {
      if (m.ecdhPubHex === state.ecdhPubKeyHex) continue;
      const existingContact = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
      if (existingContact) {
        await _sendGroupSystemMessage(existingContact, {
          type: 'group-key-update', group_id: group.groupId, group_key: newKeyHex, members: memberPayload,
        });
      }
    }

    // All deliveries accepted — commit the new roster + key locally
    await state.storage.updateGroupKey(group.groupId, newKeyHex, memberPayload);

    await refreshContacts();
    showToast(`${contact.name} added — group key rotated`, 'success');
    await openGroupMembersModal(groupDbId);
  } catch (e) {
    showToast(`Couldn't add ${contact.name}: ${e.message}. Try again — retrying re-syncs the key.`, 'error');
  } finally {
    setLoading(btn, false, 'Add');
  }
}

async function doRemoveGroupMember(groupDbId, ecdhPubHex) {
  const group = state.groups.find(g => g.id === groupDbId);
  if (!group) return;

  const newKeyHex = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

  const members = await state.storage.getGroupMembers(groupDbId);
  const remaining = members.filter(m => m.ecdhPubHex !== ecdhPubHex);
  const memberPayload = remaining.map(m => ({ name: m.name, ecdhPubHex: m.ecdhPubHex, signPubHex: m.signPubHex }));

  try {
    // Deliver the rotated key to every remaining member BEFORE committing —
    // if the relay is down, the member simply isn't removed yet.
    for (const m of remaining) {
      if (m.ecdhPubHex === state.ecdhPubKeyHex) continue;
      const c = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
      if (c) {
        await _sendGroupSystemMessage(c, {
          type: 'group-key-update', group_id: group.groupId, group_key: newKeyHex, members: memberPayload,
        });
      }
    }

    await state.storage.updateGroupKey(group.groupId, newKeyHex, memberPayload);
    await refreshContacts();
    showToast('Member removed and key rotated', 'success');
  } catch (e) {
    showToast(`Couldn't remove member: ${e.message}. Nothing changed — try again.`, 'error');
  }
}

// ─── Modals ───────────────────────────────────────────────────────────────────

function openModal(id) { $id(id).classList.remove('hidden'); }
function closeModal(id) { $id(id).classList.add('hidden'); }

function openIdentityModal() {
  // Combined share string: <ecdh-pub-hex>:<sign-pub-hex>. Contacts using the
  // legacy 130-char (ECDH-only) form remain accepted but won't get signature
  // verification — see addContact().
  $id('identity-pubkey').textContent = `${state.ecdhPubKeyHex}:${state.signPubKeyHex}`;
  $id('identity-hash').textContent = state.keyHash;
  $id('identity-identicon').innerHTML = generateIdenticon(state.keyHash || state.ecdhPubKeyHex, 72);
  try {
    $id('identity-qr').innerHTML = encodeToSvg(shareDeepLink(state.ecdhPubKeyHex, state.signPubKeyHex));
  } catch { $id('identity-qr').classList.add('hidden'); }
  // Recovery words exist only for seed-derived identities (entropy is held in
  // memory post-unlock; it lives encrypted inside the vault at rest).
  $id('btn-show-seed').classList.toggle('hidden', !state.entropyHex);
  $id('identity-no-seed-note').classList.toggle('hidden', !!state.entropyHex);
  openModal('modal-identity');
}

function fmtBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

async function openSettingsModal() {
  if (!state.storage) return; // locked — header isn't reachable, but guard anyway
  $id('setting-server-url').value = (await state.storage.getSetting('serverUrl')) || '';
  $id('setting-sync-interval').value = (await state.storage.getSetting('syncInterval')) || '15';

  // "On this device" — a live, honest inventory of everything stored here.
  const bundleBytes = (localStorage.getItem('blind-edge:identity') || '').length;
  $id('stat-identity').textContent = fmtBytes(bundleBytes);
  try {
    const stats = await state.storage.getStats();
    $id('stat-messages-label').textContent =
      `${stats.messages} message${stats.messages === 1 ? '' : 's'}, ${stats.contacts} contact${stats.contacts === 1 ? '' : 's'}${stats.groups ? `, ${stats.groups} group${stats.groups === 1 ? '' : 's'}` : ''} (stored readable)`;
    $id('stat-db').textContent = fmtBytes(stats.dbBytes);
  } catch { $id('stat-db').textContent = '—'; }
  try {
    const est = await navigator.storage?.estimate?.();
    $id('stat-total').textContent = est ? fmtBytes(est.usage) : '—';
  } catch { $id('stat-total').textContent = '—'; }

  // Install affordances: Android/desktop get the captured prompt; iOS Safari
  // gets instructions; already-installed gets nothing.
  const standalone = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone;
  const isIos = /iphone|ipad|ipod/i.test(navigator.userAgent);
  $id('btn-install-app').classList.toggle('hidden', !_deferredInstallPrompt);
  $id('btn-ios-install').classList.toggle('hidden', !(isIos && !standalone));
  $id('install-section').classList.toggle('hidden', standalone || (!_deferredInstallPrompt && !isIos));

  openModal('modal-settings');
}

async function saveSettings() {
  const serverUrl = $id('setting-server-url').value.trim();
  const syncInterval = $id('setting-sync-interval').value;

  await state.storage.setSetting('serverUrl', serverUrl);
  await state.storage.setSetting('syncInterval', syncInterval);

  closeModal('modal-settings');
  startSync(serverUrl, parseInt(syncInterval, 10));
  showToast('Settings saved', 'success');
}

async function addContact() {
  const name = $id('contact-name-input').value.trim();
  const raw = $id('contact-key-input').value.trim().toLowerCase();
  clearErr('contact-error');

  if (!name) { showErr('contact-error', 'Name is required.'); return; }

  // Accept the v2 combined form "<ecdhHex>:<signHex>" (261 chars) or the
  // legacy ECDH-only form (130 chars). Legacy contacts won't have signed
  // envelopes verified.
  let ecdhHex, signHex;
  if (raw.includes(':')) {
    [ecdhHex, signHex] = raw.split(':');
  } else {
    ecdhHex = raw;
    signHex = null;
  }

  if (ecdhHex.length !== 130 || !/^[0-9a-f]+$/.test(ecdhHex)) {
    showErr('contact-error', 'ECDH public key must be 130 hex characters (uncompressed P-256).');
    return;
  }
  if (signHex !== null && (signHex.length !== 130 || !/^[0-9a-f]+$/.test(signHex))) {
    showErr('contact-error', 'Signing public key must be 130 hex characters (uncompressed P-256).');
    return;
  }

  try {
    await SecurityManager.importPublicKeyHex(ecdhHex);
    if (signHex) await SecurityManager.importSignPublicKeyHex(signHex);
  } catch {
    showErr('contact-error', 'Invalid P-256 public key.');
    return;
  }

  try {
    await state.storage.addContact(name, ecdhHex, signHex);
    $id('contact-name-input').value = '';
    $id('contact-key-input').value = '';
    closeModal('modal-add-contact');
    await refreshContacts();
    showToast(signHex ? `${name} added` : `${name} added (legacy contact — signatures disabled)`, signHex ? 'success' : 'info');
  } catch (e) {
    showErr('contact-error', e.message.includes('UNIQUE') ? 'That key is already saved.' : 'Failed to save contact.');
  }
}

function openExportWarning() {
  $id('export-confirm-check').checked = false;
  $id('btn-confirm-export').disabled = true;
  openModal('modal-export-warning');
}

function doExportIdentityJSON() {
  const bundle = localStorage.getItem('blind-edge:identity');
  if (!bundle) return;
  closeModal('modal-export-warning');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bundle], { type: 'application/json' }));
  a.download = 'blind-edge-identity.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 60000);
  showToast('Key file downloaded — delete it after importing.', 'info');
}

// ─── Seed Phrase ──────────────────────────────────────────────────────────────

function openSeedPhraseModal() {
  $id('seed-confirm-check').checked = false;
  $id('btn-confirm-seed').disabled = true;
  $id('seed-phrase-words').classList.add('hidden');
  $id('seed-passphrase-note').classList.add('hidden');
  openModal('modal-seed-phrase');
}

async function doRevealSeedPhrase() {
  // Entropy is decrypted into memory at unlock; at rest it lives inside the
  // password-encrypted vault (see crypto.js exportIdentityBundle).
  if (!state.entropyHex) return;
  const words = await entropyToMnemonic(hexToBytes(state.entropyHex));
  const grid = $id('seed-phrase-words');
  grid.innerHTML = words.map((w, i) =>
    `<div class="seed-word"><span class="seed-num">${i + 1}</span><span class="seed-text">${w}</span></div>`
  ).join('');
  grid.classList.remove('hidden');
  $id('seed-passphrase-note').classList.remove('hidden');
}

async function doImportFromMnemonic() {
  const raw = ($id('mnemonic-input').value || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const passphrase = $id('mnemonic-passphrase').value;
  const newPassword = $id('mnemonic-new-password').value;
  const words = raw.split(' ').filter(Boolean);
  clearErr('mnemonic-error');

  if (words.length !== 12) { showErr('mnemonic-error', 'Enter exactly 12 seed words.'); return; }
  if (!validateMnemonicWords(words)) { showErr('mnemonic-error', 'One or more words are not in the BIP39 word list.'); return; }
  if (newPassword.length < 8) { showErr('mnemonic-error', 'App Password must be at least 8 characters.'); return; }

  // NOTE: must await — an unawaited call here once let invalid checksums
  // through (the rejection escaped the try/catch) and stored a Promise where
  // entropy bytes belonged.
  let entropy;
  try { entropy = await mnemonicToEntropy(words); } catch {
    showErr('mnemonic-error', 'Invalid seed phrase — checksum mismatch.'); return;
  }

  const btn = $id('btn-import-mnemonic');
  setLoading(btn, true, 'Restoring…');
  try {
    const seed64 = await mnemonicToSeed(words, passphrase);
    const { ecdh, sign } = await SecurityManager.deriveIdentityFromSeed(seed64);
    const salt = SecurityManager.generateSalt();
    const masterKey = await SecurityManager.deriveKey(newPassword, salt);
    const entropyHex = bytesToHex(entropy);
    const bundleStr = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt, entropyHex);
    localStorage.setItem('blind-edge:identity', bundleStr);
    $id('mnemonic-input').value = '';
    $id('mnemonic-passphrase').value = '';
    $id('mnemonic-new-password').value = '';
    await bootApp({ ecdh, sign, migratedFromV1: false, entropyHex, entropyWasPlaintext: false }, masterKey, salt);
    showToast('Identity restored — same keys, same address.', 'success');
  } catch (e) {
    showErr('mnemonic-error', 'Restore failed: ' + e.message);
  } finally {
    setLoading(btn, false, 'Restore Identity');
  }
}

// ─── Share Code (discovery) ───────────────────────────────────────────────────

let _codeCountdownTimer = null;

async function _hashCode(code) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code.toUpperCase()));
  return bytesToHex(new Uint8Array(buf));
}

// One click: generate a 6-char code AND register its hash with the relay.
// (The old two-step Generate → Register flow confused everyone.)
async function getShareCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I/O/0/1 — easy to say out loud
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  const code = Array.from(bytes, b => chars[b % chars.length]).join('');

  const btn = $id('btn-get-code');
  setLoading(btn, true, 'Getting code…');
  try {
    const hash = await _hashCode(code);
    const pubKey = `${state.ecdhPubKeyHex}:${state.signPubKeyHex}`;
    const serverUrl = await state.storage.getSetting('serverUrl') || DEMO_WORKER_URL;
    const res = await fetch(`${serverUrl}/api/meet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meeting_hash: hash, public_key: pubKey }),
    });
    if (!res.ok) throw new Error('relay error');
    const { expires_at } = await res.json();

    $id('my-code-display').textContent = code;
    $id('my-code-section').classList.remove('hidden');
    startCodeCountdown(expires_at);
    showToast('Code is live — tell them now.', 'success');
  } catch (e) {
    showToast('Could not get a code: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, 'Get a share code');
  }
}

function startCodeCountdown(expiresAt) {
  const el = $id('code-countdown');
  el.classList.remove('hidden');
  clearInterval(_codeCountdownTimer);
  const tick = () => {
    const ms = expiresAt - Date.now();
    if (ms <= 0) {
      el.textContent = 'expired — get a new one';
      clearInterval(_codeCountdownTimer);
      return;
    }
    const m = Math.floor(ms / 60000), s = Math.floor((ms % 60000) / 1000);
    el.textContent = `expires in ${m}:${String(s).padStart(2, '0')}`;
  };
  tick();
  _codeCountdownTimer = setInterval(tick, 1000);
}

async function lookupDiscoveryCode() {
  const code = ($id('lookup-code-input').value || '').trim().toUpperCase();
  const name = ($id('lookup-contact-name').value || '').trim();
  clearErr('lookup-error');
  if (!code) { showErr('lookup-error', 'Enter the discovery code.'); return; }
  if (!name) { showErr('lookup-error', 'Enter a name for this contact.'); return; }
  const hash = await _hashCode(code);
  const serverUrl = await state.storage.getSetting('serverUrl') || DEMO_WORKER_URL;
  const btn = $id('btn-lookup-code');
  setLoading(btn, true, 'Looking up…');
  try {
    const res = await fetch(`${serverUrl}/api/meet?hash=${hash}`);
    if (res.status === 404) { showErr('lookup-error', 'Code not found or expired.'); return; }
    if (!res.ok) throw new Error('Server error');
    const { public_key } = await res.json();
    const [ecdhHex, signHex] = public_key.includes(':') ? public_key.split(':') : [public_key, null];
    await state.storage.addContact(name, ecdhHex, signHex || null);
    closeModal('modal-add-contact');
    await refreshContacts();
    showToast(`${name} added via share code`, 'success');
  } catch (e) {
    if (!$id('lookup-error').textContent) showToast('Lookup failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, 'Look Up');
  }
}

async function downloadDB() {
  // The export is the raw SQLite file — message history in READABLE form,
  // unlike the identity backup. Make sure the user knows what they're holding.
  const ok = confirm(
    'Download your message database?\n\n' +
    'This file contains your entire message history UNENCRYPTED — unlike your ' +
    'identity backup, it is not protected by your App Password. Anyone who ' +
    'gets the file can read everything. Store it accordingly.'
  );
  if (!ok) return;
  try {
    const data = state.storage._db.export();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([data], { type: 'application/octet-stream' }));
    a.download = 'blind-edge.sqlite';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
  } catch (e) {
    showToast('DB download failed: ' + e.message, 'error');
  }
}

let _selectedTTL = 0;

function openChatSettings() {
  const contact = state.contacts.find(c => c.id === state.activeContactId);
  _selectedTTL = contact?.ttl_seconds || 0;

  const grid = $id('ttl-grid');
  grid.innerHTML = TTL_OPTIONS.map(opt => `
    <div class="ttl-chip ${opt.value === _selectedTTL ? (opt.value === 0 ? 'selected-off' : 'selected') : ''}"
         data-value="${opt.value}">${opt.label}</div>
  `).join('');

  grid.querySelectorAll('.ttl-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      _selectedTTL = parseInt(chip.dataset.value, 10);
      grid.querySelectorAll('.ttl-chip').forEach(c => c.classList.remove('selected', 'selected-off'));
      chip.classList.add(_selectedTTL === 0 ? 'selected-off' : 'selected');
    });
  });

  openModal('modal-chat-settings');
}

async function saveChatSettings() {
  if (state.activeContactId === null) return;
  await state.storage.setContactTTL(state.activeContactId, _selectedTTL);

  // Prune immediately if TTL is now set
  if (_selectedTTL) await state.storage.pruneMessages(state.activeContactId, _selectedTTL);

  closeModal('modal-chat-settings');
  await refreshContacts();

  // Refresh TTL button and notice
  const contact = state.contacts.find(c => c.id === state.activeContactId);
  const ttlBtn = $id('btn-ttl');
  const notice = $id('ttl-notice');
  if (_selectedTTL) {
    ttlBtn.textContent = formatTTL(_selectedTTL);
    ttlBtn.classList.add('ttl-active');
    notice.textContent = `Messages auto-delete after ${formatTTL(_selectedTTL)}`;
    notice.classList.remove('hidden');
    showToast(`Auto-delete set to ${TTL_OPTIONS.find(o => o.value === _selectedTTL)?.label} (this device only)`, 'success');
  } else {
    ttlBtn.textContent = 'Auto-delete';
    ttlBtn.classList.remove('ttl-active');
    notice.classList.add('hidden');
    showToast('Auto-delete off', 'info');
  }

  await renderMessages();
}

async function pruneAllExpired() {
  const contacts = await state.storage.getContacts();
  for (const c of contacts) {
    if (c.ttl_seconds) await state.storage.pruneMessages(c.id, c.ttl_seconds);
  }
}

function lockSession() {
  stopSync();
  if (state.storage) state.storage.close().catch(() => {});

  Object.assign(state, {
    masterKey: null, ecdhKeypair: null, signKeypair: null,
    ecdhPubKeyHex: null, signPubKeyHex: null, keyHash: null, entropyHex: null,
    storage: null, contacts: [], groups: [],
    activeContactId: null, activeGroupId: null, activeGroupMembers: null,
    syncTimer: null, syncRunning: false, relayStatus: 'unknown', lastEnvelope: null,
  });

  closeModal('modal-settings');
  $id('view-app').classList.add('hidden');
  $id('view-auth').classList.remove('hidden');
  $id('unlock-password').value = '';

  const hasIdentity = !!localStorage.getItem('blind-edge:identity');
  showAuthSub(hasIdentity ? 'unlock' : 'welcome');
  showToast('Locked — keys cleared from memory. Your data stays on this device.', 'info');
}

// The honest companion to burner mode: actually remove this identity and its
// message database from the device. (Lock, by contrast, removes nothing —
// it only clears keys from memory.)
async function deleteIdentityFromDevice() {
  const sure = confirm(
    'Delete this identity from this device?\n\n' +
    'Your keys and your entire message history here will be erased. ' +
    'Without your 12 recovery words or a backup file, this identity is gone forever ' +
    'and contacts will not be able to reach you.\n\nThis cannot be undone.'
  );
  if (!sure) return;

  const keyHash = state.keyHash;
  stopSync();
  if (state.storage) await state.storage.close().catch(() => {});
  try { await StorageManager.deleteIdentityData(keyHash); } catch (_) {}
  localStorage.removeItem('blind-edge:identity');

  closeModal('modal-settings');
  showToast('Identity deleted. Fresh start any time.', 'success');
  setTimeout(() => location.reload(), 800);
}

// ─── Wire events ──────────────────────────────────────────────────────────────

function openAddContactModal() {
  // Reset to the QR/key tab
  $id('section-by-key').classList.remove('hidden');
  $id('section-by-code').classList.add('hidden');
  $id('tab-by-key').classList.add('active');
  $id('tab-by-code').classList.remove('active');
  clearErr('contact-error');
  clearErr('lookup-error');
  $id('my-code-section').classList.add('hidden');
  $id('code-countdown').classList.add('hidden');
  clearInterval(_codeCountdownTimer);
  try {
    $id('add-contact-qr').innerHTML = encodeToSvg(shareDeepLink(state.ecdhPubKeyHex, state.signPubKeyHex));
  } catch { $id('add-contact-qr').classList.add('hidden'); }
  openModal('modal-add-contact');
}

function openAboutModal() {
  // "Show me the actual bytes" — render the most recent real envelope this
  // app sent. It is the user's own ciphertext; there is nothing to leak.
  const dump = $id('envelope-dump');
  if (state.lastEnvelope) {
    const e = state.lastEnvelope;
    const shortCt = e.ciphertext.length > 600
      ? e.ciphertext.slice(0, 600) + `… (${e.ciphertext.length} hex chars total)`
      : e.ciphertext;
    dump.textContent =
      `POST /api/send\n{\n  "recipient_hash": "${e.recipient_hash}",\n  "sender_hash": "${e.sender_hash}",\n  "iv": "${e.iv}",\n  "ciphertext": "${shortCt}"\n}\n\nThat's everything. No names, no text, no keys.`;
  } else {
    dump.textContent = 'Nothing sent yet this session. Send a message, then look again.';
  }
  openModal('modal-about');
}

function wireEvents() {
  // Welcome / onboarding
  $id('btn-welcome-create').addEventListener('click', () => showAuthSub('setup'));
  $id('link-welcome-import').addEventListener('click', () => showAuthSub('import'));
  $id('link-about-welcome').addEventListener('click', openAboutModal);
  $id('onboard-seed-check').addEventListener('change', e => {
    $id('btn-onboard-continue').disabled = !e.target.checked;
  });
  $id('btn-onboard-continue').addEventListener('click', showReady);
  $id('btn-onboard-skip').addEventListener('click', () => {
    $id('burner-panel').classList.toggle('hidden');
  });
  $id('btn-onboard-skip-confirm').addEventListener('click', showReady);
  $id('btn-onboard-finish').addEventListener('click', finishOnboarding);

  // Auth navigation
  $id('btn-unlock').addEventListener('click', doUnlock);
  $id('unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
  $id('link-setup').addEventListener('click', () => {
    // From the unlock screen an identity already exists on this device —
    // creating a new one overwrites it. Make that explicit.
    const ok = confirm(
      'This device already stores an identity. Creating a fresh one REPLACES it.\n\n' +
      'Without its 12 recovery words or a backup file, the current identity ' +
      'cannot be recovered. Continue?'
    );
    if (ok) showAuthSub('setup');
  });
  $id('link-import').addEventListener('click', () => showAuthSub('import'));
  $id('back-to-unlock-from-setup').addEventListener('click', () => {
    const hasIdentity = !!localStorage.getItem('blind-edge:identity');
    showAuthSub(hasIdentity ? 'unlock' : 'welcome');
  });
  $id('back-to-unlock-from-import').addEventListener('click', () => {
    const hasIdentity = !!localStorage.getItem('blind-edge:identity');
    showAuthSub(hasIdentity ? 'unlock' : 'welcome');
  });
  $id('btn-create').addEventListener('click', doCreate);
  $id('btn-import').addEventListener('click', doImport);

  // File input → populate textarea
  $id('import-file').addEventListener('change', async e => {
    const file = e.target.files[0];
    if (file) $id('import-json').value = await file.text();
  });

  // App header
  $id('btn-back').addEventListener('click', goBack);
  $id('btn-identity').addEventListener('click', openIdentityModal);
  $id('btn-settings').addEventListener('click', openSettingsModal);
  $id('btn-add-contact').addEventListener('click', openAddContactModal);

  // Compose
  const composeInput = $id('compose-input');
  composeInput.addEventListener('input', () => {
    composeInput.style.height = 'auto';
    composeInput.style.height = Math.min(composeInput.scrollHeight, 120) + 'px';
  });
  composeInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  $id('btn-send').addEventListener('click', sendMessage);

  // Add contact modal — By Key tab
  $id('tab-by-key').addEventListener('click', () => {
    $id('section-by-key').classList.remove('hidden');
    $id('section-by-code').classList.add('hidden');
    $id('tab-by-key').classList.add('active');
    $id('tab-by-code').classList.remove('active');
  });
  $id('tab-by-code').addEventListener('click', () => {
    $id('section-by-code').classList.remove('hidden');
    $id('section-by-key').classList.add('hidden');
    $id('tab-by-code').classList.add('active');
    $id('tab-by-key').classList.remove('active');
  });
  $id('btn-cancel-contact').addEventListener('click', () => closeModal('modal-add-contact'));
  $id('btn-save-contact').addEventListener('click', addContact);

  // Add contact modal — Share code tab
  $id('btn-get-code').addEventListener('click', getShareCode);
  $id('btn-lookup-code').addEventListener('click', lookupDiscoveryCode);
  $id('btn-cancel-contact-code').addEventListener('click', () => closeModal('modal-add-contact'));

  // Identity modal
  $id('btn-copy-pubkey').addEventListener('click', async () => {
    await navigator.clipboard.writeText(`${state.ecdhPubKeyHex}:${state.signPubKeyHex}`);
    showToast('Public key copied', 'success');
  });
  $id('btn-export-identity').addEventListener('click', () => { closeModal('modal-identity'); openExportWarning(); });
  $id('btn-show-seed').addEventListener('click', () => { closeModal('modal-identity'); openSeedPhraseModal(); });
  $id('export-confirm-check').addEventListener('change', e => {
    $id('btn-confirm-export').disabled = !e.target.checked;
  });
  $id('btn-confirm-export').addEventListener('click', doExportIdentityJSON);
  $id('btn-cancel-export').addEventListener('click', () => closeModal('modal-export-warning'));

  // Seed phrase modal — two deliberate steps: the checkbox only ARMS the
  // reveal button; nothing is shown until the button is explicitly clicked.
  // Unchecking re-hides the words immediately.
  $id('seed-confirm-check').addEventListener('change', e => {
    $id('btn-confirm-seed').disabled = !e.target.checked;
    if (!e.target.checked) {
      $id('seed-phrase-words').classList.add('hidden');
      $id('seed-passphrase-note').classList.add('hidden');
    }
  });
  $id('btn-confirm-seed').addEventListener('click', async () => {
    if (!$id('seed-confirm-check').checked) return;
    await doRevealSeedPhrase();
  });
  $id('btn-close-seed').addEventListener('click', () => closeModal('modal-seed-phrase'));

  // Mnemonic import
  $id('link-mnemonic-import').addEventListener('click', () => showAuthSub('mnemonic'));
  $id('back-to-import-from-mnemonic').addEventListener('click', () => showAuthSub('import'));
  $id('btn-import-mnemonic').addEventListener('click', doImportFromMnemonic);

  // Group create / members
  $id('btn-create-group').addEventListener('click', openCreateGroupModal);
  $id('btn-cancel-create-group').addEventListener('click', () => closeModal('modal-create-group'));
  $id('btn-confirm-create-group').addEventListener('click', doCreateGroup);
  $id('btn-group-members').addEventListener('click', () => {
    if (state.activeGroupId !== null) openGroupMembersModal(state.activeGroupId);
  });
  $id('btn-close-group-members').addEventListener('click', () => closeModal('modal-group-members'));
  $id('btn-add-group-member').addEventListener('click', () => {
    if (state.activeGroupId !== null) doAddGroupMember(state.activeGroupId);
  });

  // Chat settings / TTL
  $id('btn-ttl').addEventListener('click', openChatSettings);
  $id('btn-close-chat-settings').addEventListener('click', () => closeModal('modal-chat-settings'));
  $id('btn-save-ttl').addEventListener('click', saveChatSettings);
  $id('btn-close-identity').addEventListener('click', () => closeModal('modal-identity'));

  // Settings modal
  $id('btn-save-settings').addEventListener('click', saveSettings);
  $id('btn-close-settings').addEventListener('click', () => closeModal('modal-settings'));
  $id('btn-download-db').addEventListener('click', downloadDB);
  $id('btn-logout').addEventListener('click', lockSession);
  $id('btn-delete-identity').addEventListener('click', deleteIdentityFromDevice);

  // Install
  $id('btn-install-app').addEventListener('click', async () => {
    if (!_deferredInstallPrompt) return;
    _deferredInstallPrompt.prompt();
    await _deferredInstallPrompt.userChoice.catch(() => {});
    _deferredInstallPrompt = null;
    $id('btn-install-app').classList.add('hidden');
  });
  $id('btn-ios-install').addEventListener('click', () => {
    closeModal('modal-settings');
    openModal('modal-ios-install');
  });
  $id('btn-close-ios-install').addEventListener('click', () => closeModal('modal-ios-install'));

  // About modal
  $id('link-about').addEventListener('click', openAboutModal);
  $id('btn-about-from-settings').addEventListener('click', () => {
    closeModal('modal-settings');
    openAboutModal();
  });
  $id('btn-close-about').addEventListener('click', () => closeModal('modal-about'));

  // Close modals on backdrop click
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', e => { if (e.target === modal) closeModal(modal.id); });
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────────

// Capture the install prompt early (fires before DOMContentLoaded sometimes).
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  _deferredInstallPrompt = e;
});

document.addEventListener('DOMContentLoaded', () => {
  wireEvents();
  const hasIdentity = !!localStorage.getItem('blind-edge:identity');
  showAuthSub(hasIdentity ? 'unlock' : 'welcome');

  // QR deep links: a scanned code opens /#add=<key> — consume it now (stashed
  // until unlock) and react if one arrives while the app is already open.
  consumeDeepLink();
  window.addEventListener('hashchange', consumeDeepLink);
});

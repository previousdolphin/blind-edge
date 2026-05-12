import { SecurityManager } from './crypto.js';
import { StorageManager } from './storage.js';
import { hexToBytes, bytesToHex } from './hex.js';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, validateMnemonicWords } from './bip39.js';

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
  storage: null,
  contacts: [],
  groups: [],
  activeContactId: null,
  activeGroupId: null,
  activeGroupMembers: null,
  syncTimer: null,
  syncRunning: false,
};

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
  ['unlock', 'setup', 'import', 'mnemonic'].forEach(s =>
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

async function doCreate() {
  const password = $id('setup-password').value;
  const confirm = $id('setup-password-confirm').value;
  clearErr('setup-error');

  if (password.length < 8) { showErr('setup-error', 'Password must be at least 8 characters.'); return; }
  if (password !== confirm) { showErr('setup-error', 'Passwords do not match.'); return; }

  const btn = $id('btn-create');
  setLoading(btn, true, 'Generating…');

  try {
    const salt = SecurityManager.generateSalt();
    const masterKey = await SecurityManager.deriveKey(password, salt);
    const ecdhKeypair = await SecurityManager.generateIdentity();
    const signKeypair = await SecurityManager.generateSigningIdentity();
    const bundle = await SecurityManager.exportIdentityBundle(ecdhKeypair, signKeypair, masterKey, salt);
    localStorage.setItem('blind-edge:identity', bundle);
    $id('setup-password').value = '';
    $id('setup-password-confirm').value = '';
    await bootApp({ ecdh: ecdhKeypair, sign: signKeypair, migratedFromV1: false }, masterKey, salt);
  } catch (e) {
    showErr('setup-error', 'Identity generation failed: ' + e.message);
  } finally {
    setLoading(btn, false, 'Generate Identity');
  }
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
        <div class="contact-item" data-id="${c.id}">
          <div class="contact-avatar">${generateIdenticon(c.pubKeyHex, 36)}</div>
          <div class="contact-info">
            <div class="contact-name">${esc(c.name)}${c.legacy ? ' <span class="legacy-badge" title="No signing key — signature verification disabled">legacy</span>' : ''}</div>
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
        <div class="contact-item group-item" data-group-id="${g.id}">
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
  if (!seconds) return 'Timer';
  if (seconds < 3600)  return `${seconds / 60}m`;
  if (seconds < 86400) return `${seconds / 3600}h`;
  return `${seconds / 86400}d`;
}

async function openChat(contactId) {
  state.activeContactId = contactId;
  const contact = state.contacts.find(c => c.id === contactId);

  // Prune expired messages for this contact before rendering
  if (contact?.ttl_seconds) {
    await state.storage.pruneMessages(contactId, contact.ttl_seconds);
  }

  $id('panel-contacts').classList.add('hidden');
  $id('panel-chat').classList.remove('hidden');
  $id('btn-back').classList.remove('hidden');
  $id('app-title').textContent = contact ? contact.name : 'Chat';

  // TTL button
  const ttlBtn = $id('btn-ttl');
  ttlBtn.classList.remove('hidden');
  if (contact?.ttl_seconds) {
    ttlBtn.textContent = formatTTL(contact.ttl_seconds);
    ttlBtn.classList.add('ttl-active');
  } else {
    ttlBtn.textContent = 'Timer';
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
  $id('app-title').textContent = 'Blind-Edge';
  refreshContacts();
}

async function openGroupChat(groupId) {
  state.activeGroupId = groupId;
  state.activeContactId = null;
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

async function renderMessages() {
  const msgs = await state.storage.getMessages(state.activeContactId);
  $id('message-list').innerHTML = msgs.map(m => `
    <div class="message ${esc(m.direction)}">
      <div class="bubble">${esc(m.plaintext)}</div>
      ${m.direction === 'out' ? `<div class="msg-status ${esc(m.status)}">${esc(m.status)}</div>` : ''}
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
      await fetch(`${serverUrl}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_hash: group.groupHash, sender_hash: state.keyHash, ciphertext, iv }),
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

async function trySendToServer(msgId, contact, ciphertext, iv) {
  const serverUrl = (await state.storage.getSetting('serverUrl')) || '';
  if (!serverUrl) {
    showToast('Set Worker URL in Settings to send messages.', 'info');
    return;
  }

  try {
    const recipientPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
    const recipientHash = await SecurityManager.getKeyHash(recipientPubKey);

    const res = await fetch(`${serverUrl}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient_hash: recipientHash, sender_hash: state.keyHash, ciphertext, iv }),
    });

    if (res.ok) {
      await state.storage.markDelivered(msgId);
      if (state.activeContactId === contact.id) await renderMessages();
    } else {
      const body = await res.json().catch(() => ({}));
      showToast(`Send failed (${res.status}): ${body.error || 'unknown error'}`, 'error');
    }
  } catch (e) {
    showToast('Network error — message will retry on next sync.', 'error');
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
            await handleGroupInvite(parsed);
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
    // Network failure — silent
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
      const sorted = envelopes.slice().sort((a, b) => a.createdAt - b.createdAt);
      for (const env of sorted) {
        if (env.senderHash === state.keyHash) { if (env.createdAt > maxTs) maxTs = env.createdAt; continue; }
        try {
          const payload = await SecurityManager.groupDecrypt(env.ciphertext, env.iv, group.groupKey);
          if (!payload || payload.type !== 'group-msg' || payload.group_id !== group.groupId) continue;

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
        } catch (_) {}
        if (env.createdAt > maxTs) maxTs = env.createdAt;
      }
      if (maxTs > group.lastSync) await state.storage.setGroupSyncCursor(group.id, maxTs);
    } catch (_) {}
  }
  return gotNew;
}

// ─── Group management ─────────────────────────────────────────────────────────

async function handleGroupInvite(payload) {
  const existing = await state.storage.getGroupByIdHex(payload.group_id);
  if (existing) return; // already have this group

  const groupDbId = await state.storage.createGroup(
    payload.group_name, payload.group_id, payload.group_hash, payload.group_key, false
  );
  // Set sync cursor to now so we only receive new messages
  await state.storage.setGroupSyncCursor(groupDbId, Date.now());

  for (const m of payload.members) {
    // Prefer local contact name if we know this key
    const contact = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
    const name = (m.ecdhPubHex === state.ecdhPubKeyHex) ? 'You' : (contact?.name || m.name || m.ecdhPubHex.slice(0, 8) + '…');
    await state.storage.addGroupMember(groupDbId, name, m.ecdhPubHex, m.signPubHex || null);
  }

  await refreshContacts();
  showToast(`Added to group "${payload.group_name}"`, 'info');
}

async function handleGroupKeyUpdate(payload) {
  const group = await state.storage.getGroupByIdHex(payload.group_id);
  if (!group) return;
  const memberObjs = (payload.members || []).map(m => {
    const contact = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
    return {
      name: (m.ecdhPubHex === state.ecdhPubKeyHex) ? 'You' : (contact?.name || m.name || m.ecdhPubHex.slice(0, 8) + '…'),
      ecdhPubHex: m.ecdhPubHex,
      signPubHex: m.signPubHex || null,
    };
  });
  await state.storage.updateGroupKey(payload.group_id, payload.group_key, memberObjs);
  if (state.activeGroupId === group.id) {
    state.activeGroupMembers = await state.storage.getGroupMembers(group.id);
  }
}

async function _sendGroupSystemMessage(contact, payload) {
  const serverUrl = (await state.storage.getSetting('serverUrl')) || '';
  if (!serverUrl) return;
  const recipientPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
  const counter = await state.storage.incrementSentCounter(contact.id);
  const senderSignPub = contact.signPubKeyHex ? await SecurityManager.importSignPublicKeyHex(contact.signPubKeyHex) : null;
  const inner = await SecurityManager.encryptMessageEphemeral(
    JSON.stringify(payload), counter, recipientPubKey, contact.pubKeyHex, state.signKeypair.privateKey
  );
  const outerCiphertext = encodeInnerEnvelope(inner);
  const recipientHash = await SecurityManager.getKeyHash(recipientPubKey);
  await fetch(`${serverUrl}/api/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient_hash: recipientHash, sender_hash: state.keyHash, ciphertext: outerCiphertext, iv: OUTER_IV_PLACEHOLDER }),
  });
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

    const groupDbId = await state.storage.createGroup(name, groupIdHex, groupHashHex, groupKeyHex, true);
    // Add myself
    await state.storage.addGroupMember(groupDbId, 'You', state.ecdhPubKeyHex, state.signPubKeyHex);

    // Build full member list (including myself)
    const invitedContacts = checked.map(el => state.contacts.find(c => c.id === parseInt(el.value, 10))).filter(Boolean);
    for (const c of invitedContacts) {
      await state.storage.addGroupMember(groupDbId, c.name, c.pubKeyHex, c.signPubKeyHex || null);
    }

    const allMembers = await state.storage.getGroupMembers(groupDbId);
    const memberPayload = allMembers.map(m => ({ name: m.name, ecdhPubHex: m.ecdhPubHex, signPubHex: m.signPubHex }));

    // Send invites
    for (const c of invitedContacts) {
      await _sendGroupSystemMessage(c, {
        type: 'group-invite', group_id: groupIdHex, group_hash: groupHashHex,
        group_key: groupKeyHex, group_name: name, i_am_admin: false, members: memberPayload,
      });
    }

    closeModal('modal-create-group');
    await refreshContacts();
    showToast(`Group "${name}" created`, 'success');
  } catch (e) {
    showErr('create-group-error', 'Failed: ' + e.message);
  } finally {
    setLoading(btn, false, 'Create Group');
  }
}

async function openGroupMembersModal(groupDbId) {
  const group = state.groups.find(g => g.id === groupDbId) || await state.storage.getGroupByIdHex('');
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

    // Rotate key
    const newKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const newKeyHex = bytesToHex(newKeyBytes);

    // Add new member to local DB
    await state.storage.addGroupMember(groupDbId, contact.name, contact.pubKeyHex, contact.signPubKeyHex || null);
    const allMembers = await state.storage.getGroupMembers(groupDbId);
    const memberPayload = allMembers.map(m => ({ name: m.name, ecdhPubHex: m.ecdhPubHex, signPubHex: m.signPubHex }));

    // Update key locally
    await state.storage.updateGroupKey(group.groupId, newKeyHex, allMembers.map(m => ({ name: m.name, ecdhPubHex: m.ecdhPubHex, signPubHex: m.signPubHex })));

    // Send invite to new member
    await _sendGroupSystemMessage(contact, {
      type: 'group-invite', group_id: group.groupId, group_hash: group.groupHash,
      group_key: newKeyHex, group_name: group.name, i_am_admin: false, members: memberPayload,
    });

    // Send key-update to existing members (everyone except the new member)
    for (const m of allMembers) {
      if (m.ecdhPubHex === state.ecdhPubKeyHex || m.ecdhPubHex === contact.pubKeyHex) continue;
      const existingContact = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
      if (existingContact) {
        await _sendGroupSystemMessage(existingContact, {
          type: 'group-key-update', group_id: group.groupId, group_key: newKeyHex, members: memberPayload,
        });
      }
    }

    await refreshContacts();
    showToast(`${contact.name} added to group`, 'success');
    await openGroupMembersModal(groupDbId);
  } catch (e) {
    showToast('Failed to add member: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, 'Add');
  }
}

async function doRemoveGroupMember(groupDbId, ecdhPubHex) {
  const group = state.groups.find(g => g.id === groupDbId);
  if (!group) return;

  const newKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const newKeyHex = bytesToHex(newKeyBytes);

  // Remove from DB and get remaining members
  await state.storage.removeGroupMember(groupDbId, ecdhPubHex);
  const remaining = await state.storage.getGroupMembers(groupDbId);
  const memberPayload = remaining.map(m => ({ name: m.name, ecdhPubHex: m.ecdhPubHex, signPubHex: m.signPubHex }));

  // Update key locally
  await state.storage.updateGroupKey(group.groupId, newKeyHex, memberPayload);

  // Send key-update to remaining members (not myself)
  for (const m of remaining) {
    if (m.ecdhPubHex === state.ecdhPubKeyHex) continue;
    const c = state.contacts.find(c => c.pubKeyHex === m.ecdhPubHex);
    if (c) {
      await _sendGroupSystemMessage(c, {
        type: 'group-key-update', group_id: group.groupId, group_key: newKeyHex, members: memberPayload,
      });
    }
  }

  await refreshContacts();
  showToast('Member removed and key rotated', 'success');
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
  const bundle = JSON.parse(localStorage.getItem('blind-edge:identity') || 'null');
  $id('btn-show-seed').classList.toggle('hidden', !bundle?.entropy);
  openModal('modal-identity');
}

async function openSettingsModal() {
  $id('setting-server-url').value = (await state.storage.getSetting('serverUrl')) || '';
  $id('setting-sync-interval').value = (await state.storage.getSetting('syncInterval')) || '15';
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
  const bundle = JSON.parse(localStorage.getItem('blind-edge:identity') || 'null');
  if (!bundle?.entropy) return;
  const words = entropyToMnemonic(hexToBytes(bundle.entropy));
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

  let entropy;
  try { entropy = mnemonicToEntropy(words); } catch {
    showErr('mnemonic-error', 'Invalid seed phrase — checksum mismatch.'); return;
  }

  const btn = $id('btn-import-mnemonic');
  setLoading(btn, true, 'Restoring…');
  try {
    const seed64 = await mnemonicToSeed(words, passphrase);
    const { ecdh, sign } = await SecurityManager.deriveIdentityFromSeed(seed64);
    const salt = SecurityManager.generateSalt();
    const masterKey = await SecurityManager.deriveKey(newPassword, salt);
    const bundleStr = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt);
    const bundle = JSON.parse(bundleStr);
    bundle.entropy = bytesToHex(entropy);
    localStorage.setItem('blind-edge:identity', JSON.stringify(bundle));
    $id('mnemonic-input').value = '';
    $id('mnemonic-passphrase').value = '';
    $id('mnemonic-new-password').value = '';
    await bootApp({ ecdh, sign, migratedFromV1: false }, masterKey, salt);
    showToast('Identity restored from seed phrase.', 'success');
  } catch (e) {
    showErr('mnemonic-error', 'Restore failed: ' + e.message);
  } finally {
    setLoading(btn, false, 'Restore Identity');
  }
}

// ─── Discovery Code ────────────────────────────────────────────────────────────

let _myDiscoveryCode = null;

async function _hashCode(code) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code.toUpperCase()));
  return bytesToHex(new Uint8Array(buf));
}

function generateDiscoveryCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  _myDiscoveryCode = Array.from(bytes, b => chars[b % chars.length]).join('');
  $id('my-code-display').textContent = _myDiscoveryCode;
  $id('my-code-section').classList.remove('hidden');
  $id('discovery-expiry').classList.add('hidden');
  $id('btn-register-code').disabled = false;
}

async function registerDiscoveryCode() {
  if (!_myDiscoveryCode) return;
  const hash = await _hashCode(_myDiscoveryCode);
  const pubKey = `${state.ecdhPubKeyHex}:${state.signPubKeyHex}`;
  const serverUrl = await state.storage.getSetting('serverUrl') || DEMO_WORKER_URL;
  const btn = $id('btn-register-code');
  setLoading(btn, true, 'Registering…');
  try {
    const res = await fetch(`${serverUrl}/api/meet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meeting_hash: hash, public_key: pubKey }),
    });
    if (!res.ok) throw new Error('Server error');
    const { expires_at } = await res.json();
    const mins = Math.max(1, Math.round((expires_at - Date.now()) / 60000));
    $id('discovery-expiry').textContent = `Active for ~${mins} min`;
    $id('discovery-expiry').classList.remove('hidden');
    showToast('Code registered — share it verbally', 'success');
  } catch (e) {
    showToast('Registration failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, 'Register');
  }
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
    showToast(`${name} added via discovery code`, 'success');
  } catch (e) {
    if (!$id('lookup-error').textContent) showToast('Lookup failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, 'Look Up');
  }
}

async function downloadDB() {
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
    showToast(`Autodestruct set to ${TTL_OPTIONS.find(o => o.value === _selectedTTL)?.label}`, 'success');
  } else {
    ttlBtn.textContent = 'Timer';
    ttlBtn.classList.remove('ttl-active');
    notice.classList.add('hidden');
    showToast('Autodestruct off', 'info');
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
    ecdhPubKeyHex: null, signPubKeyHex: null, keyHash: null,
    storage: null, contacts: [], groups: [],
    activeContactId: null, activeGroupId: null, activeGroupMembers: null,
    syncTimer: null, syncRunning: false,
  });

  closeModal('modal-settings');
  $id('view-app').classList.add('hidden');
  $id('view-auth').classList.remove('hidden');
  $id('unlock-password').value = '';

  const hasIdentity = !!localStorage.getItem('blind-edge:identity');
  showAuthSub(hasIdentity ? 'unlock' : 'setup');
  showToast('Session locked', 'info');
}

// ─── Wire events ──────────────────────────────────────────────────────────────

function wireEvents() {
  // Auth navigation
  $id('btn-unlock').addEventListener('click', doUnlock);
  $id('unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
  $id('link-setup').addEventListener('click', () => showAuthSub('setup'));
  $id('link-import').addEventListener('click', () => showAuthSub('import'));
  $id('back-to-unlock-from-setup').addEventListener('click', () => showAuthSub('unlock'));
  $id('back-to-unlock-from-import').addEventListener('click', () => showAuthSub('unlock'));
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
  $id('btn-add-contact').addEventListener('click', () => {
    // Reset to By Key tab
    $id('section-by-key').classList.remove('hidden');
    $id('section-by-code').classList.add('hidden');
    $id('tab-by-key').classList.add('active');
    $id('tab-by-code').classList.remove('active');
    clearErr('contact-error');
    clearErr('lookup-error');
    $id('my-code-section').classList.add('hidden');
    openModal('modal-add-contact');
  });

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

  // Add contact modal — By Code tab
  $id('btn-generate-code').addEventListener('click', generateDiscoveryCode);
  $id('btn-register-code').addEventListener('click', registerDiscoveryCode);
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

  // Seed phrase modal
  $id('seed-confirm-check').addEventListener('change', async e => {
    $id('btn-confirm-seed').disabled = !e.target.checked;
    if (e.target.checked) await doRevealSeedPhrase();
    else {
      $id('seed-phrase-words').classList.add('hidden');
      $id('seed-passphrase-note').classList.add('hidden');
    }
  });
  $id('btn-confirm-seed').addEventListener('click', async () => {
    if ($id('seed-phrase-words').classList.contains('hidden')) await doRevealSeedPhrase();
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

  // About modal
  $id('link-about').addEventListener('click', () => openModal('modal-about'));
  $id('btn-close-about').addEventListener('click', () => closeModal('modal-about'));

  // Close modals on backdrop click
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', e => { if (e.target === modal) closeModal(modal.id); });
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  wireEvents();
  const hasIdentity = !!localStorage.getItem('blind-edge:identity');
  showAuthSub(hasIdentity ? 'unlock' : 'setup');
});

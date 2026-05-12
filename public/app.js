import { SecurityManager } from './crypto.js';
import { StorageManager } from './storage.js';

// Shared demo relay — works out of the box; replace with your own in Settings
const DEMO_WORKER_URL = 'https://blind-edge-api.jdo-8af.workers.dev';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

const state = {
  masterKey: null,
  keypair: null,
  pubKeyHex: null,
  keyHash: null,
  storage: null,
  contacts: [],
  activeContactId: null,
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
  ['unlock', 'setup', 'import'].forEach(s =>
    $id(`auth-${s}`).classList.toggle('hidden', s !== sub)
  );
  ['unlock-error', 'setup-error', 'import-error'].forEach(clearErr);
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
    const { publicKey, privateKey } = await SecurityManager.importIdentityBundle(bundleStr, masterKey);
    await bootApp({ publicKey, privateKey }, masterKey);
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
    const keypair = await SecurityManager.generateIdentity();
    const bundle = await SecurityManager.exportIdentityBundle(keypair, masterKey, salt);
    localStorage.setItem('blind-edge:identity', bundle);
    $id('setup-password').value = '';
    $id('setup-password-confirm').value = '';
    await bootApp(keypair, masterKey);
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
    const { publicKey, privateKey } = await SecurityManager.importIdentityBundle(jsonStr, masterKey);
    localStorage.setItem('blind-edge:identity', jsonStr);
    $id('import-password').value = '';
    $id('import-json').value = '';
    await bootApp({ publicKey, privateKey }, masterKey);
  } catch {
    showErr('import-error', 'Import failed — check password and JSON.');
  } finally {
    setLoading(btn, false, 'Import');
  }
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

async function bootApp(keypair, masterKey) {
  state.keypair = keypair;
  state.masterKey = masterKey;
  state.pubKeyHex = await SecurityManager.exportPublicKeyHex(keypair.publicKey);
  state.keyHash = await SecurityManager.getKeyHash(keypair.publicKey);

  state.storage = new StorageManager();
  await state.storage.init();

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
  state.contacts = await state.storage.getContacts();
  renderContactList();
}

function renderContactList() {
  const list = $id('contact-list');
  const empty = $id('contact-empty');

  if (!state.contacts.length) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');
  list.innerHTML = state.contacts.map(c => `
    <div class="contact-item" data-id="${c.id}">
      <div class="contact-avatar">${esc(c.name[0])}</div>
      <div class="contact-info">
        <div class="contact-name">${esc(c.name)}</div>
        <div class="contact-last-msg">${c.lastMessage ? esc(c.lastMessage.slice(0, 60)) : 'No messages yet'}</div>
      </div>
      <div class="contact-meta">
        <div class="contact-time">${fmtTime(c.lastTs)}</div>
        <div class="contact-unread">${c.unread > 0 ? c.unread : ''}</div>
      </div>
    </div>
  `).join('');

  list.querySelectorAll('.contact-item').forEach(el => {
    el.addEventListener('click', () => openChat(parseInt(el.dataset.id, 10)));
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
  $id('panel-chat').classList.add('hidden');
  $id('panel-contacts').classList.remove('hidden');
  $id('btn-back').classList.add('hidden');
  $id('btn-ttl').classList.add('hidden');
  $id('ttl-notice').classList.add('hidden');
  $id('app-title').textContent = 'Blind-Edge';
  refreshContacts();
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

async function sendMessage() {
  const input = $id('compose-input');
  const text = input.value.trim();
  if (!text || !state.activeContactId) return;

  const contact = state.contacts.find(c => c.id === state.activeContactId);
  if (!contact) return;

  input.value = '';
  input.style.height = 'auto';

  try {
    const recipientPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
    const { ciphertext, iv } = await SecurityManager.encryptMessage(
      text, recipientPubKey, state.keypair.privateKey
    );

    const msgId = await state.storage.saveOutgoing(state.activeContactId, text, ciphertext, iv);
    await renderMessages();
    scrollToBottom();
    await refreshContacts();

    await trySendToServer(msgId, contact, ciphertext, iv);
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

    for (const env of envelopes) {
      const contact = await state.storage.getContactByPubKeyHash(env.senderHash);
      if (!contact) continue;

      try {
        const senderPubKey = await SecurityManager.importPublicKeyHex(contact.pubKeyHex);
        const plaintext = await SecurityManager.decryptMessage(
          env.ciphertext, env.iv, senderPubKey, state.keypair.privateKey
        );
        const saved = await state.storage.saveIncoming(contact.id, plaintext, String(env.id));
        if (saved > 0) gotNew = true;
      } catch {
        // Unknown sender key or corrupted envelope — skip silently
      }

      if (env.createdAt > maxTs) maxTs = env.createdAt;
    }

    if (maxTs > since) await state.storage.setSetting('lastSync', String(maxTs));

    if (gotNew) {
      await refreshContacts();
      if (state.activeContactId !== null) { await renderMessages(); scrollToBottom(); }
    }
  } catch {
    // Network failure — silent
  } finally {
    state.syncRunning = false;
  }
}

// ─── Modals ───────────────────────────────────────────────────────────────────

function openModal(id) { $id(id).classList.remove('hidden'); }
function closeModal(id) { $id(id).classList.add('hidden'); }

function openIdentityModal() {
  $id('identity-pubkey').textContent = state.pubKeyHex;
  $id('identity-hash').textContent = state.keyHash;
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
  const keyHex = $id('contact-key-input').value.trim().toLowerCase();
  clearErr('contact-error');

  if (!name) { showErr('contact-error', 'Name is required.'); return; }
  if (keyHex.length !== 130 || !/^[0-9a-f]+$/.test(keyHex)) {
    showErr('contact-error', 'Public key must be 130 hex characters (uncompressed P-256).');
    return;
  }

  try {
    await SecurityManager.importPublicKeyHex(keyHex);
  } catch {
    showErr('contact-error', 'Invalid P-256 public key.');
    return;
  }

  try {
    await state.storage.addContact(name, keyHex);
    $id('contact-name-input').value = '';
    $id('contact-key-input').value = '';
    closeModal('modal-add-contact');
    await refreshContacts();
    showToast(`${name} added`, 'success');
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
    masterKey: null, keypair: null, pubKeyHex: null, keyHash: null,
    storage: null, contacts: [], activeContactId: null, syncTimer: null, syncRunning: false,
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
  $id('btn-add-contact').addEventListener('click', () => openModal('modal-add-contact'));

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

  // Add contact modal
  $id('btn-cancel-contact').addEventListener('click', () => closeModal('modal-add-contact'));
  $id('btn-save-contact').addEventListener('click', addContact);

  // Identity modal
  $id('btn-copy-pubkey').addEventListener('click', async () => {
    await navigator.clipboard.writeText(state.pubKeyHex);
    showToast('Public key copied', 'success');
  });
  $id('btn-export-identity').addEventListener('click', () => { closeModal('modal-identity'); openExportWarning(); });
  $id('export-confirm-check').addEventListener('change', e => {
    $id('btn-confirm-export').disabled = !e.target.checked;
  });
  $id('btn-confirm-export').addEventListener('click', doExportIdentityJSON);
  $id('btn-cancel-export').addEventListener('click', () => closeModal('modal-export-warning'));

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

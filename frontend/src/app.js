import * as db from "./db.js";
import { initRouter, navigate, onRouteChange, parseUserRoute } from "./router.js";
import { connectRelay } from "./ws.js";
import {
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  exportIdentityBackup,
  exportPublicKey,
  fingerprint,
  generateExchangeKeyPair,
  generateIdentityKeyPair,
  generatePaperKey,
  importExchangePublicKey,
  importIdentityBackup,
  recoveryIdForPaperKey,
  registrationPayload,
  safetyNumber,
  signChallenge,
} from "./crypto.js";
import QRCode from "qrcode";

const RELAY_WS_URL = import.meta.env.VITE_RELAY_WS_URL ?? "ws://localhost:8000/ws";
const RELAY_HTTP_URL = import.meta.env.VITE_RELAY_HTTP_URL ?? "http://localhost:8000";

const app = document.getElementById("app");

const state = {
  view: "loading", // loading | onboarding | chat
  identity: null,
  contacts: new Map(), // identityPub -> { identityPub, exchangePub, nickname }
  messages: new Map(), // peer identityPub -> [{ id, from, to, text, ts, expiresAt }]
  activeConversation: null,
  relay: null,
  relayStatus: "connecting", // connecting | open | reconnecting
  modal: null,
  routeLookup: null, // { key, status: loading|found|not-found|error|needs-onboarding, bundle? }
  onboardingMode: "create", // create | restore-file | restore-paperkey
};

const sharedKeyCache = new Map();
const loadedPeers = new Set();

export async function initApp() {
  const identity = await db.loadIdentity();
  if (identity) {
    state.identity = identity;
    for (const contact of await db.loadContacts()) state.contacts.set(contact.identityPub, contact);
    connectToRelay();
    state.view = "chat";
  } else {
    state.view = "onboarding";
  }

  onRouteChange(handleRoute);
  initRouter();
  startExpirySweep();
}

async function handleRoute(path) {
  const key = parseUserRoute(path);
  if (!key) {
    state.routeLookup = null;
    render();
    return;
  }

  if (!state.identity) {
    state.routeLookup = { key, status: "needs-onboarding" };
    render();
    return;
  }

  if (key === state.identity.identityPub) {
    navigate("/");
    return;
  }

  if (state.contacts.has(key)) {
    await ensureMessagesLoaded(key);
    state.activeConversation = key;
    state.routeLookup = null;
    render();
    return;
  }

  state.routeLookup = { key, status: "loading" };
  render();

  try {
    const resp = await fetch(`${RELAY_HTTP_URL}/u/${encodeURIComponent(key)}`);
    state.routeLookup = resp.ok
      ? { key, status: "found", bundle: await resp.json() }
      : { key, status: "not-found" };
  } catch {
    state.routeLookup = { key, status: "error" };
  }
  render();
}

function connectToRelay() {
  state.relayStatus = "connecting";
  state.relay = connectRelay({
    url: RELAY_WS_URL,
    identityKeyPair: state.identity.identityKeyPair,
    onMessage: onIncomingEnvelope,
    onStatusChange: (status) => {
      state.relayStatus = status;
      updateStatusBadge();
    },
  });
}

async function getSharedKey(peerExchangePubB64) {
  if (sharedKeyCache.has(peerExchangePubB64)) return sharedKeyCache.get(peerExchangePubB64);
  const peerKey = await importExchangePublicKey(peerExchangePubB64);
  const shared = await deriveSharedKey(state.identity.exchangeKeyPair.privateKey, peerKey);
  sharedKeyCache.set(peerExchangePubB64, shared);
  return shared;
}

async function ensureMessagesLoaded(peer) {
  if (loadedPeers.has(peer)) return;
  const records = await db.loadMessagesForPeer(peer);
  state.messages.set(
    peer,
    records.filter((m) => !m.expiresAt || m.expiresAt > Date.now()),
  );
  loadedPeers.add(peer);
}

function pushMessage(peer, record) {
  if (!state.messages.has(peer)) state.messages.set(peer, []);
  state.messages.get(peer).push(record);
}

async function onIncomingEnvelope(envelope) {
  let contact = state.contacts.get(envelope.from);
  if (!contact) {
    try {
      const resp = await fetch(`${RELAY_HTTP_URL}/u/${encodeURIComponent(envelope.from)}`);
      if (!resp.ok) return;
      const bundle = await resp.json();
      contact = {
        identityPub: envelope.from,
        exchangePub: bundle.exchange_pub,
        nickname: null,
        fp: await fingerprint(envelope.from),
      };
      state.contacts.set(contact.identityPub, contact);
      await db.saveContact(contact);
    } catch {
      return;
    }
  }

  try {
    const sharedKey = await getSharedKey(contact.exchangePub);
    const { text, expiresAt } = JSON.parse(await decryptMessage(sharedKey, envelope.ciphertext, envelope.nonce));
    const record = {
      peer: envelope.from,
      from: envelope.from,
      to: state.identity.identityPub,
      text,
      ts: envelope.ts || Date.now(),
      expiresAt: expiresAt || null,
    };
    record.id = await db.saveMessage(record);
    loadedPeers.add(envelope.from);
    pushMessage(envelope.from, record);
    render();
  } catch (err) {
    console.error("[pubkey.cc] failed to decrypt incoming message", err);
  }
}

function startExpirySweep() {
  setInterval(() => {
    const now = Date.now();
    let changed = false;
    for (const [peer, list] of state.messages) {
      const keep = list.filter((m) => !m.expiresAt || m.expiresAt > now);
      if (keep.length !== list.length) {
        changed = true;
        for (const expired of list) {
          if (expired.expiresAt && expired.expiresAt <= now) db.deleteMessage(expired.id).catch(() => {});
        }
        state.messages.set(peer, keep);
      }
    }
    // A full render() already shows fresh countdowns, so only patch the
    // DOM directly when nothing expired -- avoids re-rendering (and
    // re-scrolling) the whole conversation every second just to tick a
    // number down.
    if (changed) render();
    else tickExpiryCountdowns(now);
  }, 1000);
}

function tickExpiryCountdowns(now) {
  document.querySelectorAll(".expiry[data-expires-at]").forEach((el) => {
    el.textContent = ` · ${formatCountdown(Number(el.dataset.expiresAt), now)}`;
  });
}

// --- actions -----------------------------------------------------------

async function onCreateIdentity() {
  const identityKeyPair = await generateIdentityKeyPair();
  const exchangeKeyPair = await generateExchangeKeyPair();
  const identityPub = await exportPublicKey(identityKeyPair.publicKey);
  const exchangePub = await exportPublicKey(exchangeKeyPair.publicKey);
  const identity = { identityKeyPair, exchangeKeyPair, identityPub, exchangePub, fp: await fingerprint(identityPub) };
  await finishIdentitySetup(identity);
}

async function onRestoreIdentity(form) {
  const errorEl = document.getElementById("restore-error");
  const data = new FormData(form);
  const file = data.get("file");
  const passphrase = String(data.get("passphrase") || "");

  if (!file || !file.size) {
    if (errorEl) errorEl.textContent = "Choose a backup file.";
    return;
  }

  try {
    const backup = JSON.parse(await file.text());
    const identity = await importIdentityBackup(backup, passphrase);
    await finishIdentitySetup(identity);
  } catch (err) {
    console.error("[pubkey.cc] restore failed", err);
    if (errorEl) errorEl.textContent = "Couldn't restore that backup, check the file and passphrase.";
  }
}

// Shared by both onboarding paths: a freshly generated identity and one
// decrypted from a backup file both need saving locally, registering with
// the relay's directory (harmless to repeat if already registered), and a
// transition into the chat shell.
async function finishIdentitySetup(identity) {
  await db.saveIdentity(identity);
  state.identity = identity;

  // /register requires proof identity_pub is actually controlled by the
  // caller, or anyone could publish an attacker-chosen exchange_pub under
  // someone else's identity_pub and hijack their directory entry.
  const payload = registrationPayload(identity.identityPub, identity.exchangePub, null);
  const signature = await signChallenge(identity.identityKeyPair.privateKey, payload);

  await fetch(`${RELAY_HTTP_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      identity_pub: identity.identityPub,
      exchange_pub: identity.exchangePub,
      signature,
    }),
  });

  connectToRelay();
  state.view = "chat";

  const pendingKey = state.routeLookup?.status === "needs-onboarding" ? state.routeLookup.key : null;
  state.routeLookup = null;
  render();
  if (pendingKey) navigate(`/u/${pendingKey}`);
}

async function onSendMessage(form) {
  const peer = state.activeConversation;
  const contact = peer && state.contacts.get(peer);
  if (!contact) return;

  const data = new FormData(form);
  const text = String(data.get("text") || "").trim();
  if (!text) return;
  const ttlMs = Number(data.get("ttl")) || 0;
  const expiresAt = ttlMs ? Date.now() + ttlMs : null;

  const sharedKey = await getSharedKey(contact.exchangePub);
  const { ciphertext, nonce } = await encryptMessage(sharedKey, JSON.stringify({ text, expiresAt }));

  try {
    state.relay.send({ to: peer, ciphertext, nonce, ts: Date.now() });
  } catch (err) {
    console.error("[pubkey.cc] failed to send, not connected to relay", err);
    const errorEl = document.getElementById("send-error");
    if (errorEl) errorEl.textContent = "Not connected right now. Try again in a moment.";
    return;
  }

  const record = { peer, from: state.identity.identityPub, to: peer, text, ts: Date.now(), expiresAt };
  record.id = await db.saveMessage(record);
  pushMessage(peer, record);
  form.reset();
  render();
}

async function onOpenShareModal() {
  const link = `${window.location.origin}/u/${state.identity.identityPub}`;
  const qrDataUrl = await QRCode.toDataURL(link, { margin: 1, width: 220 });
  state.modal = { type: "share", link, qrDataUrl };
  render();
}

function onCopyText(el) {
  navigator.clipboard?.writeText(el.dataset.text);
}

function onOpenBackupModal() {
  state.modal = { type: "backup" };
  render();
}

function onOpenPaperKeyModal() {
  state.modal = { type: "paperkey", paperKey: generatePaperKey() };
  render();
}

// The paper key doubles as an "add this device" credential: entering it
// during onboarding on any device restores the same identity there, so
// there's no separate device-linking flow to build.
async function onConfirmPaperKey() {
  const paperKey = state.modal?.paperKey;
  if (!paperKey) return;

  const recoveryId = await recoveryIdForPaperKey(paperKey);
  const blob = await exportIdentityBackup(state.identity, paperKey);
  await fetch(`${RELAY_HTTP_URL}/recovery/${recoveryId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(blob),
  });

  state.modal = null;
  render();
}

async function onRestorePaperKey(form) {
  const errorEl = document.getElementById("restore-paperkey-error");
  const data = new FormData(form);
  const paperKey = String(data.get("paperKey") || "")
    .trim()
    .toUpperCase();

  if (!paperKey) {
    if (errorEl) errorEl.textContent = "Enter your paper key.";
    return;
  }

  try {
    const recoveryId = await recoveryIdForPaperKey(paperKey);
    const resp = await fetch(`${RELAY_HTTP_URL}/recovery/${recoveryId}`);
    if (!resp.ok) throw new Error("no recovery blob for this paper key");
    const blob = await resp.json();
    const identity = await importIdentityBackup(blob, paperKey);
    await finishIdentitySetup(identity);
  } catch (err) {
    console.error("[pubkey.cc] paper key restore failed", err);
    if (errorEl) errorEl.textContent = "Couldn't restore with that paper key, check it and try again.";
  }
}

async function onExportBackup(form) {
  const errorEl = document.getElementById("backup-error");
  const data = new FormData(form);
  const passphrase = String(data.get("passphrase") || "");
  const confirm = String(data.get("confirm") || "");

  if (passphrase.length < 8) {
    if (errorEl) errorEl.textContent = "Passphrase must be at least 8 characters.";
    return;
  }
  if (passphrase !== confirm) {
    if (errorEl) errorEl.textContent = "Passphrases don't match.";
    return;
  }

  const backup = await exportIdentityBackup(state.identity, passphrase);
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `pubkeycc-identity-${(state.identity.fp || "backup").replace(/\s+/g, "-")}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);

  state.modal = null;
  render();
}

async function onOpenVerifyModal() {
  const peer = state.activeConversation;
  if (!peer) return;
  const contact = state.contacts.get(peer);
  const sn = await safetyNumber(state.identity.identityPub, peer);
  state.modal = { type: "verify", peer, safetyNumber: sn, nickname: contact?.nickname };
  render();
}

async function onSaveNickname(el) {
  const peer = el.dataset.peer;
  const input = document.getElementById("nickname-input");
  const nickname = input.value.trim() || null;
  const contact = state.contacts.get(peer);
  if (contact) {
    contact.nickname = nickname;
    await db.saveContact(contact);
  }
  state.modal = null;
  render();
}

async function onAddContact() {
  const lookup = state.routeLookup;
  if (!lookup || lookup.status !== "found") return;
  const contact = {
    identityPub: lookup.key,
    exchangePub: lookup.bundle.exchange_pub,
    nickname: null,
    fp: await fingerprint(lookup.key),
  };
  state.contacts.set(contact.identityPub, contact);
  await db.saveContact(contact);
  loadedPeers.add(contact.identityPub);
  state.activeConversation = contact.identityPub;
  state.routeLookup = null;
  render();
}

async function onConfirmWipe() {
  // relay.close() (not relay.socket.close()) is required here: closing the
  // raw socket alone would just trigger ws.js's own reconnect logic, which
  // has no idea the app is about to wipe everything and navigate away.
  state.relay?.close();
  await db.wipeAll();
  window.location.href = "/";
}

const handlers = {
  "create-identity": onCreateIdentity,
  "show-restore-file": () => {
    state.onboardingMode = "restore-file";
    render();
  },
  "show-restore-paperkey": () => {
    state.onboardingMode = "restore-paperkey";
    render();
  },
  "show-create": () => {
    state.onboardingMode = "create";
    render();
  },
  "open-conversation": (el) => navigate(`/u/${el.dataset.peer}`),
  "open-share-modal": onOpenShareModal,
  "open-backup-modal": onOpenBackupModal,
  "open-paperkey-modal": onOpenPaperKeyModal,
  "confirm-paperkey": onConfirmPaperKey,
  "open-verify-modal": onOpenVerifyModal,
  "close-modal": () => {
    state.modal = null;
    render();
  },
  "copy-text": onCopyText,
  "save-nickname": onSaveNickname,
  "add-contact": onAddContact,
  "dismiss-lookup": () => {
    state.routeLookup = null;
    navigate("/");
  },
  panic: () => {
    state.modal = { type: "wipe-confirm" };
    render();
  },
  "confirm-wipe": onConfirmWipe,
};

app.addEventListener("click", (event) => {
  if (event.target.classList.contains("modal-overlay")) {
    state.modal = null;
    render();
    return;
  }
  const el = event.target.closest("[data-action]");
  if (!el) return;
  handlers[el.dataset.action]?.(el, event);
});

const formHandlers = {
  "send-message": onSendMessage,
  "restore-identity": onRestoreIdentity,
  "restore-paperkey": onRestorePaperKey,
  "export-backup": onExportBackup,
};

app.addEventListener("submit", (event) => {
  const form = event.target.closest("[data-action]");
  const handler = form && formHandlers[form.dataset.action];
  if (!handler) return;
  event.preventDefault();
  handler(form);
});

// --- rendering -----------------------------------------------------------

function render() {
  const draft = captureComposerDraft();

  let html;
  if (state.view === "onboarding") html = renderOnboarding();
  else if (state.view === "chat") html = renderChatShell();
  else html = `<div class="onboarding"><p>Loading…</p></div>`;

  app.innerHTML = html + renderModalHtml();

  restoreComposerDraft(draft);
  scrollMessagesToBottom();
}

// render() rebuilds the whole DOM via innerHTML, which would otherwise wipe
// whatever's half-typed in the composer on every unrelated state change
// (a message arriving, a reconnect, an expiry sweep). The textarea has no
// `value` in the template, so nothing survives an innerHTML replace unless
// explicitly carried over like this.
function captureComposerDraft() {
  const textarea = document.querySelector('.composer textarea[name="text"]');
  if (!textarea) return null;
  const focused = document.activeElement === textarea;
  return {
    peer: state.activeConversation,
    text: textarea.value,
    focused,
    selectionStart: focused ? textarea.selectionStart : null,
    selectionEnd: focused ? textarea.selectionEnd : null,
  };
}

function restoreComposerDraft(draft) {
  if (!draft || !draft.text || draft.peer !== state.activeConversation) return;
  const textarea = document.querySelector('.composer textarea[name="text"]');
  if (!textarea) return;
  textarea.value = draft.text;
  if (draft.focused) {
    textarea.focus();
    textarea.setSelectionRange(draft.selectionStart, draft.selectionEnd);
  }
}

function renderOnboarding() {
  const pending =
    state.routeLookup?.status === "needs-onboarding"
      ? `<p class="hint">You'll be connected with <code>${escapeHtml(shortKey(state.routeLookup.key))}</code> once your identity is ready.</p>`
      : "";

  if (state.onboardingMode === "restore-file") {
    return `
      <div class="onboarding">
        <h1>pubkey.cc</h1>
        <p>Restore your identity from a backup file. This device never sees your passphrase, decryption happens locally.</p>
        ${pending}
        <form data-action="restore-identity">
          <input type="file" name="file" accept="application/json" required />
          <input type="password" name="passphrase" placeholder="Backup passphrase" required />
          <p class="hint error" id="restore-error"></p>
          <button type="submit" class="primary">Restore Identity</button>
        </form>
        <button type="button" data-action="show-create" class="link">Back</button>
      </div>
    `;
  }

  if (state.onboardingMode === "restore-paperkey") {
    return `
      <div class="onboarding">
        <h1>pubkey.cc</h1>
        <p>Restore your identity with a paper key, the same code you'd use to add another device to this account.</p>
        ${pending}
        <form data-action="restore-paperkey">
          <input type="text" name="paperKey" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" required autocomplete="off" autocapitalize="characters" />
          <p class="hint error" id="restore-paperkey-error"></p>
          <button type="submit" class="primary">Restore Identity</button>
        </form>
        <button type="button" data-action="show-create" class="link">Back</button>
      </div>
    `;
  }

  return `
    <div class="onboarding">
      <h1>pubkey.cc</h1>
      <p>No email, phone number, or password. Your identity is a keypair generated on this device, right now.</p>
      ${pending}
      <button data-action="create-identity" class="primary">Create Identity</button>
      <button type="button" data-action="show-restore-paperkey" class="link">Restore with a paper key</button>
      <button type="button" data-action="show-restore-file" class="link">Restore from a backup file</button>
    </div>
  `;
}

function renderChatShell() {
  const contacts = [...state.contacts.values()].sort((a, b) =>
    (a.nickname || a.identityPub).localeCompare(b.nickname || b.identityPub),
  );

  const contactItems =
    contacts
      .map(
        (c) => `
      <div class="contact ${c.identityPub === state.activeConversation ? "active" : ""}" data-action="open-conversation" data-peer="${escapeHtml(c.identityPub)}">
        <span class="name">${escapeHtml(c.nickname || shortKey(c.identityPub))}</span>
        <span class="fp">${escapeHtml(c.fp || shortKey(c.identityPub))}</span>
      </div>
    `,
      )
      .join("") || `<div class="hint" style="padding:1rem;">No contacts yet. Share your link to get started.</div>`;

  return `
    <div class="shell">
      <aside class="sidebar">
        <div class="sidebar-header">
          <div>
            <div>pubkey.cc</div>
            <div class="fp">${escapeHtml(state.identity.fp || shortKey(state.identity.identityPub))}</div>
          </div>
          <div class="header-actions">
            <button data-action="open-share-modal" title="Share your identity">Share</button>
            <button data-action="open-backup-modal" title="Backup your identity to a file">Backup</button>
            <button data-action="open-paperkey-modal" title="Get a paper key for recovery or a new device">Paper Key</button>
          </div>
        </div>
        <div class="contact-list">${contactItems}</div>
        <div class="sidebar-footer">
          <button data-action="panic" class="danger">Panic / Clear Session</button>
        </div>
      </aside>
      <div class="main">
        ${renderLookupBanner()}
        ${renderConversation()}
      </div>
    </div>
  `;
}

function renderLookupBanner() {
  const lookup = state.routeLookup;
  if (!lookup || lookup.status === "needs-onboarding") return "";
  if (lookup.status === "loading") {
    return `<div class="banner"><span>Looking up <code>${escapeHtml(shortKey(lookup.key))}</code>…</span></div>`;
  }
  if (lookup.status === "not-found") {
    return `<div class="banner"><span>No identity registered at <code>${escapeHtml(shortKey(lookup.key))}</code>.</span><button data-action="dismiss-lookup">Dismiss</button></div>`;
  }
  if (lookup.status === "error") {
    return `<div class="banner"><span>Couldn't reach the relay to look that up.</span><button data-action="dismiss-lookup">Dismiss</button></div>`;
  }
  if (lookup.status === "found") {
    return `<div class="banner"><span>Add <code>${escapeHtml(shortKey(lookup.key))}</code> as a contact?</span>
      <span><button data-action="add-contact">Add</button> <button data-action="dismiss-lookup">Dismiss</button></span>
    </div>`;
  }
  return "";
}

function computeConversationStatus(peer) {
  const contact = peer && state.contacts.get(peer);
  const hasKey = Boolean(contact?.exchangePub);
  if (!hasKey) return { statusClass: "", statusText: "Establishing session…" };
  if (state.relayStatus === "open") return { statusClass: "secure", statusText: "End-to-end encrypted" };
  if (state.relayStatus === "replaced") {
    return { statusClass: "warn", statusText: "Open in another tab" };
  }
  return {
    statusClass: "warn",
    statusText: state.relayStatus === "connecting" ? "Connecting…" : "Reconnecting…",
  };
}

// Patches the status badge directly rather than a full render(): relay
// status flips (connecting/open/reconnecting) happen independently of any
// content change, and a full re-render would wipe whatever the user has
// half-typed in the composer (the textarea has no `value` in the
// template, so an innerHTML replace clears it).
function updateStatusBadge() {
  const badge = document.querySelector(".chat-header .status");
  if (!badge) return;
  const { statusClass, statusText } = computeConversationStatus(state.activeConversation);
  badge.className = `status ${statusClass}`.trim();
  badge.innerHTML = `<span class="dot"></span>${escapeHtml(statusText)}`;
}

function renderConversation() {
  const peer = state.activeConversation;
  if (!peer) {
    return `<div class="empty-state">Select a contact, or share your link to start a conversation.</div>`;
  }

  const contact = state.contacts.get(peer);
  const messages = state.messages.get(peer) || [];
  const { statusClass, statusText } = computeConversationStatus(peer);

  const messageItems =
    messages
      .map((m) => {
        const dir = m.from === state.identity.identityPub ? "out" : "in";
        const expiry = m.expiresAt
          ? `<span class="expiry" data-expires-at="${m.expiresAt}"> · ${formatCountdown(m.expiresAt)}</span>`
          : "";
        return `
        <div class="message ${dir}">
          <div>${escapeHtml(m.text)}</div>
          <div class="meta">${formatTime(m.ts)}${expiry}</div>
        </div>
      `;
      })
      .join("") || `<div class="empty-state">No messages yet.</div>`;

  return `
    <div class="chat-header">
      <div>
        <div>${escapeHtml(contact?.nickname || shortKey(peer))}</div>
        <div class="status ${statusClass}"><span class="dot"></span>${statusText}</div>
      </div>
      <button data-action="open-verify-modal">Verify</button>
    </div>
    <div class="messages" id="messages">${messageItems}</div>
    <p class="hint error composer-error" id="send-error"></p>
    <form class="composer" data-action="send-message">
      <select name="ttl" title="Disappearing message timer">
        <option value="0">Off</option>
        <option value="10000">10s</option>
        <option value="60000">1m</option>
        <option value="3600000">1h</option>
      </select>
      <textarea name="text" rows="1" placeholder="Message…" autocomplete="off"></textarea>
      <button type="submit" class="primary">Send</button>
    </form>
  `;
}

function renderModalHtml() {
  const modal = state.modal;
  if (!modal) return "";

  if (modal.type === "share") {
    return `
      <div class="modal-overlay">
        <div class="modal">
          <h2>Your identity</h2>
          <p class="hint">Share this link so someone can start an encrypted conversation with you. Anyone with the link can see your public key, that's expected, it's public.</p>
          <img class="qr" src="${modal.qrDataUrl}" width="180" height="180" alt="QR code for your identity link" />
          <input type="text" readonly value="${escapeHtml(modal.link)}" onclick="this.select()" />
          <div class="actions">
            <button data-action="copy-text" data-text="${escapeHtml(modal.link)}">Copy link</button>
            <button data-action="close-modal">Close</button>
          </div>
        </div>
      </div>
    `;
  }

  if (modal.type === "backup") {
    return `
      <div class="modal-overlay">
        <div class="modal">
          <h2>Backup identity</h2>
          <p class="hint">Encrypts your private keys with a passphrase and downloads a file. Keep both somewhere safe: this is the only way to restore your identity on another device or browser. There is no recovery if you lose the passphrase.</p>
          <form data-action="export-backup">
            <input type="password" name="passphrase" placeholder="Choose a passphrase (min 8 characters)" required minlength="8" />
            <input type="password" name="confirm" placeholder="Confirm passphrase" required minlength="8" />
            <p class="hint error" id="backup-error"></p>
            <div class="actions">
              <button type="button" data-action="close-modal">Cancel</button>
              <button type="submit" class="primary">Download backup</button>
            </div>
          </form>
        </div>
      </div>
    `;
  }

  if (modal.type === "paperkey") {
    return `
      <div class="modal-overlay">
        <div class="modal">
          <h2>Paper key</h2>
          <p class="hint">Write this down and keep it somewhere safe: on paper, not a screenshot. Anyone with this key can restore your identity, so treat it like a password. Use it on another device to add it to this account, or to recover if you lose this one.</p>
          <div class="safety-number">${escapeHtml(modal.paperKey)}</div>
          <div class="actions">
            <button data-action="copy-text" data-text="${escapeHtml(modal.paperKey)}">Copy</button>
            <button data-action="confirm-paperkey" class="primary">I've saved this, Enable</button>
          </div>
        </div>
      </div>
    `;
  }

  if (modal.type === "verify") {
    return `
      <div class="modal-overlay">
        <div class="modal">
          <h2>Verify contact</h2>
          <p class="hint">Compare this number with your contact over a separate channel (in person, a phone call) to confirm nobody is intercepting your connection.</p>
          <div class="safety-number">${escapeHtml(modal.safetyNumber)}</div>
          <label class="hint" for="nickname-input">Nickname</label>
          <input id="nickname-input" type="text" value="${escapeHtml(modal.nickname || "")}" placeholder="e.g. Alice" />
          <div class="actions">
            <button data-action="save-nickname" data-peer="${escapeHtml(modal.peer)}">Save</button>
            <button data-action="close-modal">Close</button>
          </div>
        </div>
      </div>
    `;
  }

  if (modal.type === "wipe-confirm") {
    return `
      <div class="modal-overlay">
        <div class="modal">
          <h2>Clear everything?</h2>
          <p class="hint">This immediately deletes your identity, contacts, and message history from this device. It cannot be undone, you would need a new identity link.</p>
          <div class="actions">
            <button data-action="close-modal">Cancel</button>
            <button data-action="confirm-wipe" class="danger">Wipe now</button>
          </div>
        </div>
      </div>
    `;
  }

  return "";
}

function scrollMessagesToBottom() {
  const el = document.getElementById("messages");
  if (el) el.scrollTop = el.scrollHeight;
}

function shortKey(key) {
  return key ? `${key.slice(0, 12)}…${key.slice(-6)}` : "";
}

function formatTime(ts) {
  return ts ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
}

function formatCountdown(expiresAt, now = Date.now()) {
  const secs = Math.max(0, Math.round((expiresAt - now) / 1000));
  if (secs >= 60) return `expires in ${Math.ceil(secs / 60)}m`;
  return `expires in ${secs}s`;
}

function escapeHtml(str) {
  return String(str).replace(
    /[&<>"']/g,
    (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch],
  );
}

// Local-first persistence. Everything here lives only on this device, the
// server never sees any of it. CryptoKey objects are stored directly since
// IndexedDB's structured clone algorithm supports them natively.

const DB_NAME = "pubkeycc";
const DB_VERSION = 1;

let dbPromise = null;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("identity")) {
        db.createObjectStore("identity", { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains("contacts")) {
        db.createObjectStore("contacts", { keyPath: "identityPub" });
      }
      if (!db.objectStoreNames.contains("messages")) {
        const store = db.createObjectStore("messages", { keyPath: "id", autoIncrement: true });
        store.createIndex("byPeer", "peer");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function getDb() {
  if (!dbPromise) dbPromise = openDb();
  return dbPromise;
}

function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveIdentity(identity) {
  const db = await getDb();
  const store = db.transaction("identity", "readwrite").objectStore("identity");
  await reqToPromise(store.put({ id: "me", ...identity }));
}

export async function loadIdentity() {
  const db = await getDb();
  const store = db.transaction("identity", "readonly").objectStore("identity");
  return reqToPromise(store.get("me"));
}

export async function saveContact(contact) {
  const db = await getDb();
  const store = db.transaction("contacts", "readwrite").objectStore("contacts");
  await reqToPromise(store.put(contact));
}

export async function loadContacts() {
  const db = await getDb();
  const store = db.transaction("contacts", "readonly").objectStore("contacts");
  return reqToPromise(store.getAll());
}

export async function saveMessage(message) {
  const db = await getDb();
  const store = db.transaction("messages", "readwrite").objectStore("messages");
  return reqToPromise(store.add(message));
}

export async function deleteMessage(id) {
  const db = await getDb();
  const store = db.transaction("messages", "readwrite").objectStore("messages");
  await reqToPromise(store.delete(id));
}

export async function loadMessagesForPeer(peer) {
  const db = await getDb();
  const store = db.transaction("messages", "readonly").objectStore("messages").index("byPeer");
  return reqToPromise(store.getAll(peer));
}

export async function wipeAll() {
  const db = await getDb();
  await Promise.all(
    ["identity", "contacts", "messages"].map((name) =>
      reqToPromise(db.transaction(name, "readwrite").objectStore(name).clear()),
    ),
  );
}

import { exportPublicKey, signChallenge } from "./crypto.js";

const MAX_RECONNECT_DELAY_MS = 30000;

// Connects to the relay and proves ownership of the identity key by signing
// a server-issued challenge. Never sends anything but public keys and
// already-encrypted envelopes.
//
// Reconnects automatically with exponential backoff on any unexpected close
// (server restart, network blip). No special resume logic is needed on
// reconnect: re-authenticating triggers the server's flush_queue() the same
// way a fresh connection does, so anything sent while we were offline
// arrives as soon as the new connection is authenticated.
export function connectRelay({ url, identityKeyPair, onReady, onMessage, onStatusChange }) {
  let socket = null;
  let reconnectAttempt = 0;
  let reconnectTimer = null;
  let closedByCaller = false;

  function setStatus(status) {
    onStatusChange?.(status);
  }

  function connect() {
    setStatus(reconnectAttempt === 0 ? "connecting" : "reconnecting");
    socket = new WebSocket(url);

    socket.addEventListener("message", async (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "challenge") {
        const [pubkey, signature] = await Promise.all([
          exportPublicKey(identityKeyPair.publicKey),
          signChallenge(identityKeyPair.privateKey, data.nonce),
        ]);
        socket.send(JSON.stringify({ pubkey, signature }));
        return;
      }

      if (data.type === "ready") {
        reconnectAttempt = 0;
        setStatus("open");
        onReady?.(data.pubkey);
        return;
      }

      if (data.type === "message") {
        onMessage?.(data);
      }
    });

    socket.addEventListener("close", () => {
      if (closedByCaller) return;
      scheduleReconnect();
    });

    socket.addEventListener("error", () => {
      socket.close();
    });
  }

  function scheduleReconnect() {
    setStatus("reconnecting");
    const delayMs = Math.min(MAX_RECONNECT_DELAY_MS, 1000 * 2 ** reconnectAttempt);
    reconnectAttempt += 1;
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, delayMs);
  }

  connect();

  return {
    get socket() {
      return socket;
    },
    send(envelope) {
      if (socket?.readyState !== WebSocket.OPEN) {
        throw new Error("Not connected to the relay.");
      }
      socket.send(JSON.stringify({ type: "message", ...envelope }));
    },
    close() {
      closedByCaller = true;
      clearTimeout(reconnectTimer);
      socket?.close();
    },
  };
}

import { exportPublicKey, signChallenge } from "./crypto.js";

// Connects to the relay and proves ownership of the identity key by signing
// a server-issued challenge. Never sends anything but public keys and
// already-encrypted envelopes.
export function connectRelay({ url, identityKeyPair, onReady, onMessage }) {
  const socket = new WebSocket(url);

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
      onReady?.(data.pubkey);
      return;
    }

    if (data.type === "message") {
      onMessage?.(data);
    }
  });

  return {
    socket,
    send(envelope) {
      socket.send(JSON.stringify({ type: "message", ...envelope }));
    },
  };
}

// Browser side of the WebAuthn fingerprint factor.
// WebAuthn uses binary buffers; our JSON API uses base64url strings.
const b64uToBuf = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
    credentials: "same-origin",
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const err = new Error(data.error || "Request failed");
    err.data = data;
    throw err;
  }
  return data;
}

// Enrol this laptop's fingerprint reader for the current user.
async function registerFingerprint() {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support WebAuthn.");
  }
  const opts = await postJSON("/webauthn/register/options");
  opts.challenge = b64uToBuf(opts.challenge);
  opts.user.id = b64uToBuf(opts.user.id);
  (opts.excludeCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));

  // Browser shows the Windows Hello / Touch ID prompt here.
  const cred = await navigator.credentials.create({ publicKey: opts });

  return postJSON("/webauthn/register/verify", {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  });
}

// Prove presence of the enrolled fingerprint (login step 3).
async function loginWithFingerprint() {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support WebAuthn.");
  }
  const opts = await postJSON("/webauthn/login/options");
  opts.challenge = b64uToBuf(opts.challenge);
  (opts.allowCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));

  const cred = await navigator.credentials.get({ publicKey: opts });

  return postJSON("/webauthn/login/verify", {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
  });
}

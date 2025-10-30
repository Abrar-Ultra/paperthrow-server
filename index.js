/**
 * PaperThrow Firebase Functions (Spark-compatible version)
 * Endpoints: /handshake, /sendEvent, /getResults, /getWind
 */
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

if (!admin.apps.length) admin.initializeApp();
const db = admin.firestore();

// Helpers
function json(res, code, obj) {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.status(code).send(JSON.stringify(obj));
}
function bad(res, msg, code = 400) { json(res, code, { ok: false, error: msg }); }
function hmacSign(input) {
  const secret = "dev_secret_spark_tier"; // static on Spark
  return crypto.createHmac("sha256", secret).update(input).digest("hex");
}
function newToken() { return crypto.randomBytes(16).toString("hex"); }
async function verifySession(sessionToken, sig) {
  if (!sessionToken || !sig) return null;
  const doc = await db.collection("sessions").doc(sessionToken).get();
  if (!doc.exists) return null;
  if (sig !== hmacSign(sessionToken)) return null;
  return doc.ref;
}

// Handshake
exports.handshake = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return bad(res, "POST required");
  const { version, checksum, deviceId } = req.body || {};
  if (!version || !checksum || !deviceId) return bad(res, "Missing params");

  const sessionToken = newToken();
  const signature = hmacSign(sessionToken);

  await db.collection("sessions").doc(sessionToken).set({
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    version,
    checksum,
    deviceId,
    signature,
    hits: 0,
    throws: 0,
    score: 0,
  });

  json(res, 200, { ok: true, sessionToken, signature });
});

// Send Event
exports.sendEvent = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return bad(res, "POST required");
  const { sessionToken, clientSignature, eventType, timestamp, data } = req.body || {};
  const ref = await verifySession(sessionToken, clientSignature);
  if (!ref) return bad(res, "Invalid session", 401);

  await ref.collection("events").add({
    eventType,
    data,
    timestamp: timestamp || Date.now(),
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  if (eventType === "throw") {
    await ref.update({ throws: admin.firestore.FieldValue.increment(1) });
  } else if (eventType === "basket_hit") {
    await ref.update({
      hits: admin.firestore.FieldValue.increment(1),
      score: admin.firestore.FieldValue.increment(10),
    });
  } else if (eventType === "score_update" && data) {
    try {
      const parsed = JSON.parse(data);
      if (typeof parsed.totalScore === "number") {
        await ref.update({ score: parsed.totalScore });
      }
    } catch (_) {}
  }

  json(res, 200, { ok: true });
});

// Get Results
exports.getResults = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return bad(res, "POST required");
  const { sessionToken, clientSignature } = req.body || {};
  const ref = await verifySession(sessionToken, clientSignature);
  if (!ref) return bad(res, "Invalid session", 401);

  const doc = await ref.get();
  const d = doc.data() || {};
  const throws_ = d.throws || 0;
  const hits = d.hits || 0;
  const accuracy = throws_ > 0 ? hits / throws_ : 0;
  const score = d.score || hits * 10;

  json(res, 200, { ok: true, score, hits, shots: throws_, accuracy, timeTaken: 0 });
});

// Get Wind
exports.getWind = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") return bad(res, "POST required");
  const { sessionToken, clientSignature } = req.body || {};
  const ref = await verifySession(sessionToken, clientSignature);
  if (!ref) return bad(res, "Invalid session", 401);

  const seed = crypto.createHash("md5").update(sessionToken).digest("hex");
  const r = (i) => parseInt(seed.substr(i * 2, 2), 16) / 255;
  const wind = {
    x: (r(0) - 0.5) * 0.4,
    y: 0,
    z: (r(1) - 0.5) * 0.4,
    strength: 0.8 + r(2) * 0.8,
  };

  await ref.update({ lastWind: wind });
  json(res, 200, wind);
});
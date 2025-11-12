// server.js — version propre et sûre
import express from "express";
import cors from "cors";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Utilitaires fichiers ----------
const CODES_FILE = "./codes.json";          // codes permanents (dans le repo)
const BINDINGS_FILE = "./bindings.json";    // liaisons code<->device (éphémère)

function ensureFile(path, defaultContent) {
  if (!fs.existsSync(path)) {
    fs.writeFileSync(path, defaultContent, "utf8");
  }
}

// Charge un tableau de codes (ou tableau vide)
function loadCodes() {
  ensureFile(CODES_FILE, JSON.stringify(["ABC123"], null, 2));
  try {
    const raw = fs.readFileSync(CODES_FILE, "utf8");
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.map(String) : [];
  } catch (e) {
    console.error("loadCodes() error:", e);
    return [];
  }
}

// Charge/Enregistre les bindings
function loadBindings() {
  ensureFile(BINDINGS_FILE, JSON.stringify({}, null, 2));
  try {
    const raw = fs.readFileSync(BINDINGS_FILE, "utf8");
    return JSON.parse(raw) || {};
  } catch (e) {
    console.error("loadBindings() error:", e);
    return {};
  }
}
function saveBindings(bindings) {
  fs.writeFileSync(BINDINGS_FILE, JSON.stringify(bindings, null, 2), "utf8");
}

// Normalisation des codes (insensible casse, espaces, Unicode)
function normalizeCode(c) {
  return (c || "")
    .toString()
    .normalize("NFKC")
    .replace(/\s+/g, "")
    .toUpperCase();
}

// ---------- Middlewares ----------
app.use(cors({ origin: true }));
app.use(express.json()); // PAS body-parser

// ---------- Healthcheck & debug ----------
app.get("/", (req, res) => {
  res.send("OK - utilisez /api/auth (POST).");
});
app.get("/api/auth", (req, res) => {
  res.json({ ok: true, message: "Auth server running. Use POST for auth." });
});
app.get("/api/debug/codes", (req, res) => {
  try {
    res.json({ ok: true, codes: loadCodes() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- Auth ----------
app.post("/api/auth", (req, res) => {
  try {
    const { token, fingerprint, code } = req.body || {};
    if (!fingerprint || typeof fingerprint !== "string") {
      return res.status(400).json({ ok: false, error: "Missing fingerprint" });
    }

    let bindings = loadBindings();

    // 1) Token (session existante)
    if (token) {
      const found = Object.values(bindings).find(b => b.token === token);
      if (!found) return res.status(401).json({ ok: false, error: "Invalid token" });
      if (found.fingerprint !== fingerprint) {
        return res.status(403).json({ ok: false, error: "Token does not match this device" });
      }
      return res.json({ ok: true, mode: "token" });
    }

    // 2) Code (nouvel accès)
    if (!code || typeof code !== "string") {
      return res.status(400).json({ ok: false, error: "Missing code" });
    }

    const codes = loadCodes().map(normalizeCode);
    const entered = normalizeCode(code);
    const isAllowed = codes.includes(entered);
    if (!isAllowed) return res.status(401).json({ ok: false, error: "Bad code" });

    // Code déjà lié ?
    const existingKey = Object.keys(bindings).find(
      k => normalizeCode(bindings[k].code) === entered
    );

    if (!existingKey) {
      // Première utilisation : lier ce device au code
      const id = uuidv4();
      const newBinding = {
        id, code, fingerprint, token: uuidv4(), createdAt: new Date().toISOString()
      };
      bindings[id] = newBinding;
      saveBindings(bindings);
      return res.json({ ok: true, mode: "bound-first-time", token: newBinding.token });
    }

    // Déjà lié
    const binding = bindings[existingKey];
    if (binding.fingerprint === fingerprint) {
      return res.json({ ok: true, mode: "same-device", token: binding.token });
    }
    return res.status(403).json({ ok: false, error: "Ce code a déjà été utilisé sur un autre appareil." });

  } catch (e) {
    console.error("POST /api/auth error:", e);
    return res.status(500).json({ ok: false, error: e.message || "Internal Server Error" });
  }
});

// (facultatif) Admin
app.get("/api/admin/bindings", (req, res) => {
  res.json(loadBindings());
});
app.post("/api/admin/reset-code", (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ ok: false, error: "Missing code" });
  const entered = normalizeCode(code);

  const bindings = loadBindings();
  let changed = false;
  for (const id of Object.keys(bindings)) {
    if (normalizeCode(bindings[id].code) === entered) {
      delete bindings[id]; changed = true;
    }
  }
  if (changed) { saveBindings(bindings); return res.json({ ok: true }); }
  return res.status(404).json({ ok: false, error: "Code not found" });
});

// ---------- Démarrage ----------
app.listen(PORT, () => {
  console.log(`Auth server on port ${PORT}`);
});

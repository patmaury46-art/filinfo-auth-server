// server.js
// -----------------------------------------
// Serveur d'authentification pour Fil Info
// - Codes autorisés lus depuis codes.json
// - 1 code = 1 machine (liaison persistée)
// - Tolérant casse/espaces/Unicode sur la saisie
// - Endpoints admin (bindings + reset-code)
// -----------------------------------------

import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";

const app = express();
const PORT = process.env.PORT || 3000;

/* ============================
   CODES AUTORISÉS (codes.json)
   - Par défaut: ./codes.json (à la racine du repo)
   - Surchargable via: process.env.CODES_FILE
============================ */
const CODES_FILE = process.env.CODES_FILE || "./codes.json";

function ensureCodesFile() {
  if (!fs.existsSync(CODES_FILE)) {
    // Fichier minimal si absent
    fs.writeFileSync(CODES_FILE, JSON.stringify(["ABC123"], null, 2), "utf8");
  }
}

function loadCodes() {
  ensureCodesFile();
  try {
    const raw = fs.readFileSync(CODES_FILE, "utf8");
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.map(String) : [];
  } catch {
    return [];
  }
}

// Normalisation: retire espaces, casse non sensible, normalise Unicode
function normalizeCode(c) {
  return (c || "")
    .toString()
    .normalize("NFKC")
    .replace(/\s+/g, "")
    .toUpperCase();
}

/* ============================
   BINDINGS (liaisons code <-> device <-> token)
   - Par défaut: ./bindings.json (non persistant sur Render en plan gratuit)
   - Surchargable via: process.env.BINDINGS_FILE
   - Si vous voulez la vraie persistance Render: utilisez un Disk et /data/bindings.json
============================ */
const BINDINGS_FILE = process.env.BINDINGS_FILE || "./bindings.json";

function loadBindings() {
  if (!fs.existsSync(BINDINGS_FILE)) {
    fs.writeFileSync(BINDINGS_FILE, JSON.stringify({}), "utf8");
  }
  const raw = fs.readFileSync(BINDINGS_FILE, "utf8");
  try {
    return JSON.parse(raw) || {};
  } catch {
    return {};
  }
}

function saveBindings(bindings) {
  fs.writeFileSync(BINDINGS_FILE, JSON.stringify(bindings, null, 2), "utf8");
}

/* ============================
   MIDDLEWARES
============================ */
app.use(cors({
  // En production, restreignez à votre domaine Netlify:
  // origin: "https://votre-site.netlify.app"
  origin: true,
  credentials: false
}));
app.use(bodyParser.json());

/* ============================
   HEALTHCHECK
============================ */
app.get("/", (req, res) => {
  res.send("OK - utilisez /api/auth (POST).");
});

app.get("/api/auth", (req, res) => {
  res.json({ ok: true, message: "Le serveur d'authentification des fichiers est en cours d'exécution. Utilisez POST pour l'authentification." });
});

/* ============================
   AUTH
   POST /api/auth
   body:
     - soit { token, fingerprint }
     - soit { code, fingerprint }
============================ */
app.post("/api/auth", (req, res) => {
  const { token, fingerprint, code } = req.body || {};
  if (!fingerprint || typeof fingerprint !== "string") {
    return res.status(400).json({ ok: false, error: "Missing fingerprint" });
  }

  let bindings = loadBindings();

  // 1) Vérification par token (session déjà liée)
  if (token) {
    const found = Object.values(bindings).find(b => b.token === token);
    if (!found) {
      return res.status(401).json({ ok: false, error: "Invalid token" });
    }
    if (found.fingerprint !== fingerprint) {
      return res.status(403).json({ ok: false, error: "Token does not match this device" });
    }
    return res.json({ ok: true, mode: "token" });
  }

  // 2) Vérification par code (nouvel accès)
  if (!code || typeof code !== "string") {
    return res.status(400).json({ ok: false, error: "Missing code" });
  }

  // Lecture des codes depuis codes.json + normalisation
  const codes = loadCodes().map(normalizeCode);
  const entered = normalizeCode(code);

  const isAllowed = codes.includes(entered);
  if (!isAllowed) {
    return res.status(401).json({ ok: false, error: "Bad code" });
  }

  // Ce code est-il déjà lié ?
  const existingKey = Object.keys(bindings).find(k => normalizeCode(bindings[k].code) === entered);

  if (!existingKey) {
    // Première utilisation : on lie le code à ce device et on délivre un token
    const id = uuidv4();
    const newBinding = {
      id,
      code,               // on garde la forme d'origine
      fingerprint,
      token: uuidv4(),
      createdAt: new Date().toISOString()
    };
    bindings[id] = newBinding;
    saveBindings(bindings);
    return res.json({
      ok: true,
      mode: "bound-first-time",
      token: newBinding.token
    });
  }

  // Déjà lié
  const binding = bindings[existingKey];
  if (binding.fingerprint === fingerprint) {
    // Même machine : on renvoie le token existant
    return res.json({
      ok: true,
      mode: "same-device",
      token: binding.token
    });
  }

  // Machine différente -> refus
  return res.status(403).json({
    ok: false,
    error: "Ce code a déjà été utilisé sur un autre appareil."
  });
});

/* ============================
   ADMIN (facultatif)
   - /api/admin/bindings : liste les liaisons
   - /api/admin/reset-code : libère un code
============================ */
app.get("/api/admin/bindings", (req, res) => {
  const bindings = loadBindings();
  res.json(bindings);
});

app.post("/api/admin/reset-code", (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ ok: false, error: "Missing code" });
  const entered = normalizeCode(code);

  const bindings = loadBindings();
  let changed = false;
  for (const id of Object.keys(bindings)) {
    if (normalizeCode(bindings[id].code) === entered) {
      delete bindings[id];
      changed = true;
    }
  }
  if (changed) {
    saveBindings(bindings);
    return res.json({ ok: true });
  }
  return res.status(404).json({ ok: false, error: "Code not found" });
});

/* ============================ */
app.listen(PORT, () => {
  console.log(`Fil info auth server running on port ${PORT}`);
});

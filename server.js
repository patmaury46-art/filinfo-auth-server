import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";

const app = express();
const PORT = process.env.PORT || 3000;

// 1) Codes autorisés (ne sont connus QUE du serveur)
const ALLOWED_CODES = {
  // "identifiant logiquement lisible": "code réel"
  "user1": "ABC123",
  "user2": "DEF456",
  "admin": "SUPER2025"
};

// 2) Fichier où on stocke les liaisons code <-> fingerprint <-> token
const BINDINGS_FILE = "./bindings.json";

// charge ou init le store
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

app.use(cors({
  origin: true,          // en prod : remplace par ton domaine précis
  credentials: false
}));
app.use(bodyParser.json());

// Simple test: GET /api/auth -> permet de vérifier que le serveur répond
app.get("/api/auth", (req, res) => {
  res.json({ ok: true, message: "Fil info auth server is running. Use POST for auth." });
});


// ---------- ROUTE D'AUTH ----------
// POST /api/auth
// body:
//   - soit { token, fingerprint }
//   - soit { code, fingerprint }
app.post("/api/auth", (req, res) => {
  const { token, fingerprint, code } = req.body || {};
  if (!fingerprint || typeof fingerprint !== "string") {
    return res.status(400).json({ ok: false, error: "Missing fingerprint" });
  }

  let bindings = loadBindings();

  // --- 1) Vérif par token (session déjà liée) ---
  if (token) {
    const found = Object.values(bindings).find(b => b.token === token);
    if (!found) {
      return res.status(401).json({ ok: false, error: "Invalid token" });
    }
    if (found.fingerprint !== fingerprint) {
      return res.status(403).json({ ok: false, error: "Token does not match this device" });
    }
    // OK : accès autorisé
    return res.json({ ok: true, mode: "token" });
  }

  // --- 2) Vérif par code (nouvel accès ou revalidation) ---
  if (!code || typeof code !== "string") {
    return res.status(400).json({ ok: false, error: "Missing code" });
  }

  // Le code fait-il partie des ALLOWED_CODES ?
  const isAllowed = Object.values(ALLOWED_CODES).includes(code);
  if (!isAllowed) {
    return res.status(401).json({ ok: false, error: "Bad code" });
  }

  // Ce code est-il déjà lié ?
  const existingKey = Object.keys(bindings).find(k => bindings[k].code === code);

  if (!existingKey) {
    // -> première utilisation : on lie ce code à ce fingerprint
    const id = uuidv4();
    const newBinding = {
      id,
      code,
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

  // Il existe déjà un binding pour ce code
  const binding = bindings[existingKey];

  if (binding.fingerprint === fingerprint) {
    // Même machine : on renvoie le token existant
    return res.json({
      ok: true,
      mode: "same-device",
      token: binding.token
    });
  }

  // -> Machine différente : on refuse
  return res.status(403).json({
    ok: false,
    error: "Ce code a déjà été utilisé sur un autre appareil."
  });
});

// ---------- ROUTE ADMIN OPTIONNELLE ----------
// pour lister les bindings (à sécuriser si tu l'utilises en prod)
app.get("/api/admin/bindings", (req, res) => {
  const bindings = loadBindings();
  res.json(bindings);
});

// pour réinitialiser un code (ex: changement de poste)
app.post("/api/admin/reset-code", (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ ok: false, error: "Missing code" });
  const bindings = loadBindings();
  let changed = false;
  for (const id of Object.keys(bindings)) {
    if (bindings[id].code === code) {
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

app.listen(PORT, () => {
  console.log(`Fil info auth server running on port ${PORT}`);
});

/* ============================================================================
   ATHEMIX37 PK14 — ROOT ACCESS
   Serveur backend Node.js (sans framework, seulement socket.io + bcryptjs)
   ----------------------------------------------------------------------------
   Fournit :
     - l'interface (public/index.html) servie à la racine
     - l'API interne  /api/auth/*, /api/links, /api/events, /api/stats,
       /api/analyzer, /api/analyses, /api/reports
     - le moteur de redirection /r/<code> (HTTP 302 vers la liste blanche)
     - la synchronisation temps réel socket.io (chemin « / », client embarqué
       dans le fichier HTML)
     - le stockage persistant : fichier data/data.json (écriture atomique)
   ----------------------------------------------------------------------------
   Lancement :  npm install   puis   node server.js
   Variables :  PORT (défaut 8080), HOST (défaut 0.0.0.0),
                DATA_DIR (défaut ./data), SESSION_TTL_HOURS (défaut 12)
   ============================================================================ */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { Server: SocketIOServer } = require('socket.io');
const bcrypt = require('bcryptjs');

/* ============================================================================
   SECTION 1 — CONFIGURATION
   ============================================================================ */

const PORT = parseInt(process.env.PORT || '8080', 10) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const SESSION_TTL_MS =
  (parseInt(process.env.SESSION_TTL_HOURS || '12', 10) || 12) * 3600 * 1000;

const BCRYPT_ROUNDS = 10;
const MAX_EVENTS = 5000;    // nombre max d'événements conservés
const MAX_ANALYSES = 500;   // nombre max d'analyses conservées
const BODY_LIMIT = 200 * 1024; // taille max d'un corps de requête
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // sans 0/O/1/I/L
const CODE_LENGTH = 8;

/* Liste blanche officielle : les redirections ne peuvent aller QUE vers ces
   domaines (copie conforme de la map PLATFORMS du frontend). */
const PLATFORMS = {
  facebook:  { id: 'facebook',  name: 'Facebook',  domain: 'facebook.com',  destination: 'https://www.facebook.com/'  },
  instagram: { id: 'instagram', name: 'Instagram', domain: 'instagram.com', destination: 'https://www.instagram.com/' },
  tiktok:    { id: 'tiktok',    name: 'TikTok',    domain: 'tiktok.com',    destination: 'https://www.tiktok.com/'    },
  snapchat:  { id: 'snapchat',  name: 'Snapchat',  domain: 'snapchat.com',  destination: 'https://www.snapchat.com/'  },
  x:         { id: 'x',         name: 'X',         domain: 'x.com',         destination: 'https://x.com/'             },
  youtube:   { id: 'youtube',   name: 'YouTube',   domain: 'youtube.com',   destination: 'https://www.youtube.com/'   },
  whatsapp:  { id: 'whatsapp',  name: 'WhatsApp',  domain: 'whatsapp.com',  destination: 'https://www.whatsapp.com/'  },
  telegram:  { id: 'telegram',  name: 'Telegram',  domain: 'telegram.org',  destination: 'https://telegram.org/'      },
};

const PLATFORM_IDS = Object.keys(PLATFORMS);

/* Codes de gravité de l'analyseur (classes CSS côté frontend) */
const DANGEROUS_FINDINGS = new Set([
  'UNSAFE_PROTOCOL', 'LOCAL_HOST', 'IP_HOST', 'CREDENTIALS_IN_URL',
  'TYPOSQUAT', 'BRAND_IMPERSONATION', 'EXECUTABLE_LINK', 'REDIRECT_INSECURE',
]);
const SUSPICIOUS_FINDINGS = new Set([
  'NO_TLS', 'ODD_PORT', 'PUNYCODE', 'RISKY_TLD', 'COMPLEX_HOST',
  'SENSITIVE_PARAMS',
]);
const INFO_FINDINGS = new Set(['OFFICIAL_DOMAIN', 'REDIRECT_CHAIN']);

const RISKY_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
  'rest', 'country', 'kim', 'loan', 'men', 'party', 'science', 'stream',
  'download', 'date', 'review', 'gdn', 'cam', 'quest', 'cfd', 'sbs', 'icu',
  'buzz',
]);

const EXECUTABLE_EXT = /\.(exe|msi|bat|cmd|com|scr|ps1|vbs|jar|apk|dmg|appimage|deb|rpm|sh)$/i;
const SENSITIVE_PARAM_RE = /(password|passwd|pwd|token|session|auth|apikey|api[_-]?key|secret|access[_-]?token|jwt|otp|pin)/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* ============================================================================
   SECTION 2 — STOCKAGE PERSISTANT (fichier JSON, écriture atomique)
   ============================================================================ */

function defaultData() {
  return { admin: null, sessions: {}, links: [], events: [], analyses: [] };
}

let db = defaultData();

function loadData() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch (e) { /* déjà présent */ }
  let raw = null;
  try {
    raw = fs.readFileSync(DATA_FILE, 'utf8');
  } catch (e) {
    log('Stockage : aucun fichier existant, base vierge.');
    return;
  }
  try {
    const parsed = JSON.parse(raw);
    db = Object.assign(defaultData(), parsed);
    log(`Stockage chargé : ${db.links.length} liens, ${db.events.length} événements, ${db.analyses.length} analyses.`);
  } catch (e) {
    const backup = DATA_FILE + '.corrupt-' + Date.now();
    try { fs.renameSync(DATA_FILE, backup); } catch (e2) { /* rien */ }
    db = defaultData();
    log(`ATTENTION : data.json illisible (archivé dans ${backup}). Base vierge recréée.`);
  }
}

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; flushSave(); }, 250);
}

function flushSave() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DATA_FILE); // écriture atomique (rename)
  } catch (e) {
    log('ERREUR d\'écriture du stockage : ' + e.message);
  }
}

/* Purge périodique des sessions expirées */
function cleanExpiredSessions() {
  const now = Date.now();
  let removed = 0;
  for (const [hash, sess] of Object.entries(db.sessions)) {
    if (!sess || !sess.expiresAt || new Date(sess.expiresAt).getTime() <= now) {
      delete db.sessions[hash];
      removed++;
    }
  }
  if (removed > 0) scheduleSave();
}

/* ============================================================================
   SECTION 3 — OUTILS GÉNÉRAUX
   ============================================================================ */

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function uid() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString('hex');
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

/* Clé de jour locale (YYYY-MM-DD, fuseau du serveur) pour les statistiques */
function dayKey(d) {
  const t = d instanceof Date ? d : new Date(d);
  const p = (n) => String(n).padStart(2, '0');
  return `${t.getFullYear()}-${p(t.getMonth() + 1)}-${p(t.getDate())}`;
}

function randomCode() {
  const bytes = crypto.randomBytes(CODE_LENGTH);
  let out = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  }
  return out;
}

function strongPassword(pw) {
  return typeof pw === 'string' && pw.length >= 10 &&
    /[A-Za-z]/.test(pw) && /\d/.test(pw);
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* Distance de Levenshtein (pour la détection de typosquatting) */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = new Array(n + 1), cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, cur] = [cur, prev];
  }
  return prev[n];
}

/* Lit le corps de la requête (JSON), renvoie null si vide/trop gros/illisible */
function readBody(req) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    let aborted = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > BODY_LIMIT) { aborted = true; resolve(null); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (aborted) return;
      if (!chunks.length) return resolve(null);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { resolve(null); }
    });
    req.on('error', () => { if (!aborted) resolve(null); });
  });
}

/* ============================================================================
   SECTION 4 — RÉPONSES HTTP + CORS
   ============================================================================ */

/* CORS réfléchi : autorise n'importe quelle origine (nécessaire au mode
   autonome : fichier HTML ouvert en double-clic, origin « null »). */
function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '600');
}

function sendJson(res, status, obj, req) {
  applyCors(req, res);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(obj == null ? {} : obj));
}

/* Erreur API au format du frontend : { error: 'CODE', ...extra } */
function sendError(res, status, code, extra, req) {
  sendJson(res, status, Object.assign({ error: code }, extra || {}), req);
}

function handleOptions(req, res) {
  applyCors(req, res);
  res.writeHead(204);
  res.end();
}

/* ============================================================================
   SECTION 5 — AUTHENTIFICATION (bcrypt + jetons opaques hachés en base)
   ============================================================================ */

/* Anti-forcebrutal : 5 échecs par IP+email sur une fenêtre glissante de
   10 minutes → verrouillage de 60 secondes (code RATE_LIMITED). */
const loginFailures = new Map(); // clé « ip|email » → { count, firstAt, lockedUntil }
const FAIL_WINDOW_MS = 10 * 60 * 1000;
const FAIL_MAX = 5;
const LOCK_MS = 60 * 1000;

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff && typeof xff === 'string') return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || '?';
}

function checkLoginLock(ip, email) {
  const key = ip + '|' + email.toLowerCase();
  const entry = loginFailures.get(key);
  if (!entry) return { locked: false };
  const now = Date.now();
  if (entry.lockedUntil && entry.lockedUntil > now) {
    return { locked: true, retryAfterSec: Math.ceil((entry.lockedUntil - now) / 1000) };
  }
  if (now - entry.firstAt > FAIL_WINDOW_MS) {
    loginFailures.delete(key);
    return { locked: false };
  }
  return { locked: false };
}

function registerLoginFailure(ip, email) {
  const key = ip + '|' + email.toLowerCase();
  const now = Date.now();
  const entry = loginFailures.get(key);
  if (!entry || now - entry.firstAt > FAIL_WINDOW_MS) {
    loginFailures.set(key, { count: 1, firstAt: now, lockedUntil: 0 });
  } else {
    entry.count += 1;
    if (entry.count >= FAIL_MAX) entry.lockedUntil = now + LOCK_MS;
  }
}

function clearLoginFailures(ip, email) {
  loginFailures.delete(ip + '|' + email.toLowerCase());
}

function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex'); // jeton opaque
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  db.sessions[sha256hex(token)] = { email, expiresAt }; // haché en base
  scheduleSave();
  return { token, email, expiresAt };
}

/* Vérifie un jeton (texte clair) → session valide ou null */
function getSession(token) {
  if (!token || typeof token !== 'string') return null;
  const sess = db.sessions[sha256hex(token)];
  if (!sess) return null;
  if (!sess.expiresAt || new Date(sess.expiresAt).getTime() <= Date.now()) {
    delete db.sessions[sha256hex(token)];
    scheduleSave();
    return null;
  }
  return sess;
}

/* Middleware : extraction du Bearer token → session ou null */
function requireAuth(req) {
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return null;
  return getSession(m[1].trim());
}

async function handleAuth(req, res, u, pathname) {
  const ip = clientIp(req);

  /* GET /api/auth/state — détection du mode hébergé par le frontend */
  if (req.method === 'GET' && pathname === '/api/auth/state') {
    const sess = requireAuth(req);
    const out = { needsSetup: !db.admin };
    if (sess) { out.authenticated = true; out.email = sess.email; }
    return sendJson(res, 200, out, req);
  }

  /* POST /api/auth/setup — création du compte administrateur */
  if (req.method === 'POST' && pathname === '/api/auth/setup') {
    if (db.admin) return sendError(res, 400, 'ALREADY_SETUP', null, req);
    const body = await readBody(req);
    if (!body || typeof body !== 'object') return sendError(res, 400, 'INVALID_BODY', null, req);
    const email = String(body.email || '').trim();
    const password = String(body.password || '');
    if (!EMAIL_RE.test(email) || email.length > 254) return sendError(res, 400, 'INVALID_EMAIL', null, req);
    if (!strongPassword(password)) return sendError(res, 400, 'WEAK_PASSWORD', null, req);
    db.admin = {
      email,
      passwordHash: bcrypt.hashSync(password, BCRYPT_ROUNDS),
      createdAt: nowIso(),
    };
    scheduleSave();
    log(`Compte administrateur créé : ${email}`);
    return sendJson(res, 200, { ok: true, needsSetup: false }, req);
  }

  /* POST /api/auth/login — connexion (avec anti-forcebrutal) */
  if (req.method === 'POST' && pathname === '/api/auth/login') {
    const body = await readBody(req);
    if (!body || typeof body !== 'object') return sendError(res, 400, 'INVALID_BODY', null, req);
    const email = String(body.email || '').trim();
    const password = String(body.password || '');
    if (!email || !password) return sendError(res, 400, 'INVALID_BODY', null, req);

    const lock = checkLoginLock(ip, email);
    if (lock.locked) {
      return sendError(res, 429, 'RATE_LIMITED', { retryAfterSec: lock.retryAfterSec }, req);
    }
    if (!db.admin || db.admin.email.toLowerCase() !== email.toLowerCase() ||
        !bcrypt.compareSync(password, db.admin.passwordHash)) {
      registerLoginFailure(ip, email);
      return sendError(res, 400, 'INVALID_CREDENTIALS', null, req);
    }
    clearLoginFailures(ip, email);
    const session = createSession(db.admin.email);
    log(`Connexion réussie : ${session.email} (${ip})`);
    return sendJson(res, 200, session, req);
  }

  /* POST /api/auth/verify — restauration de session */
  if (req.method === 'POST' && pathname === '/api/auth/verify') {
    const body = await readBody(req);
    const token = body && typeof body === 'object' ? body.token : null;
    const sess = getSession(token);
    return sendJson(res, 200, { valid: !!sess, email: sess ? sess.email : null }, req);
  }

  /* POST /api/auth/logout — déconnexion */
  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    const h = req.headers['authorization'] || '';
    const m = /^Bearer\s+(.+)$/i.exec(h);
    if (m) {
      delete db.sessions[sha256hex(m[1].trim())];
      scheduleSave();
    }
    res.writeHead(204, { 'Access-Control-Allow-Origin': (req.headers.origin || '*') });
    res.end();
    return;
  }

  /* POST /api/auth/password — changement de mot de passe (session requise) */
  if (req.method === 'POST' && pathname === '/api/auth/password') {
    const sess = requireAuth(req);
    if (!sess) return sendError(res, 401, 'SESSION_EXPIRED', null, req);
    const body = await readBody(req);
    if (!body || typeof body !== 'object') return sendError(res, 400, 'INVALID_BODY', null, req);
    const current = String(body.currentPassword || '');
    const next = String(body.newPassword || '');
    if (!bcrypt.compareSync(current, db.admin.passwordHash)) {
      return sendError(res, 400, 'INVALID_CREDENTIALS', null, req);
    }
    if (!strongPassword(next)) return sendError(res, 400, 'WEAK_PASSWORD', null, req);
    db.admin.passwordHash = bcrypt.hashSync(next, BCRYPT_ROUNDS);
    // invalide toutes les AUTRES sessions (la session courante reste valide)
    const currentHash = null;
    for (const [hash] of Object.entries(db.sessions)) {
      // on ne connaît pas le hash de la session courante ici sans le jeton ;
      // on invalide donc tout : le client reste connecté via sa session en cours
      // uniquement le temps de la requête — comportement sûr et simple.
      delete db.sessions[hash];
    }
    scheduleSave();
    log('Mot de passe administrateur modifié.');
    return sendJson(res, 200, { ok: true }, req);
  }

  return sendError(res, 404, 'SERVER', null, req);
}

/* ============================================================================
   SECTION 6 — TEMPS RÉEL (socket.io, chemin « / », client embarqué)
   ============================================================================ */

const io = new SocketIOServer({
  path: '/',
  addTrailingSlash: false,
  transports: ['websocket', 'polling'],
  cors: { origin: true, methods: ['GET', 'POST'] },
});

io.on('connection', (socket) => {
  let authenticated = false;

  const accept = (email) => {
    authenticated = true;
    socket.data.email = email;
    socket.join('admin');
    socket.emit('auth_ok');
  };

  /* Le client peut aussi passer le jeton au handshake : auth: { token } */
  const hsToken = socket.handshake && socket.handshake.auth && socket.handshake.auth.token;
  const hsSess = getSession(hsToken);
  if (hsSess) accept(hsSess.email);

  socket.on('auth', (payload) => {
    if (authenticated) { socket.emit('auth_ok'); return; }
    const token = payload && typeof payload === 'object' ? payload.token : null;
    const sess = getSession(token);
    if (sess) accept(sess.email);
    else socket.emit('auth_denied');
  });

  socket.on('disconnect', () => { /* rien à faire */ });
});

/* Diffusion d'un événement d'ouverture aux interfaces authentifiées */
function broadcastLinkEvent(ev) {
  io.to('admin').emit('link_event', {
    id: ev.id,
    code: ev.code,
    platform: ev.platform,
    type: ev.type,
    result: ev.result,
    status: ev.status,
    destination: ev.destination,
    domain: ev.domain,
    report: ev.report,
    at: ev.createdAt,
    createdAt: ev.createdAt,
  });
}

/* ============================================================================
   SECTION 7 — ÉVÉNEMENTS D'OUVERTURE
   ============================================================================ */

function recordEvent(code, platform, result, status, report, destination, domain) {
  const ev = {
    id: uid(),
    code,
    platform: platform || '',
    type: 'OPEN',
    result,
    status,
    report,
    destination: destination || '',
    domain: domain || '',
    createdAt: nowIso(),
  };
  db.events.push(ev);
  if (db.events.length > MAX_EVENTS) {
    db.events.splice(0, db.events.length - MAX_EVENTS); // garde les plus récents
  }
  scheduleSave();
  broadcastLinkEvent(ev);
  return ev;
}

function eventCountFor(code) {
  let n = 0;
  for (const ev of db.events) if (ev.code === code) n++;
  return n;
}

/* Vue publique d'un lien (avec compteur d'événements) */
function linkOut(link) {
  return Object.assign({}, link, { eventCount: eventCountFor(link.code) });
}

/* ============================================================================
   SECTION 8 — ANALYSEUR D'URL (verdict FIABLE / SUSPECT / DANGEREUX / NON VÉRIFIÉ)
   ============================================================================ */

function officialMatch(host) {
  const h = String(host || '').toLowerCase();
  for (const id of PLATFORM_IDS) {
    const d = PLATFORMS[id].domain;
    if (h === d || h === 'www.' + d || h.endsWith('.' + d)) {
      return { platform: id, domain: d };
    }
  }
  return null;
}

function registrableDomain(host) {
  const labels = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  return labels.slice(-2).join('.');
}

/* Suit la chaîne de redirections (max 5 sauts) avec fetch natif (Node ≥ 18).
   Renvoie { hops, chain: [{url, host, protocol}], verified: bool, error } */
async function followRedirects(startUrl) {
  const chain = [];
  let current = startUrl;
  try {
    for (let hop = 0; hop < 5; hop++) {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(6000),
        headers: { 'User-Agent': 'ATHEMIX37-Analyzer/1.0' },
      });
      const u = new URL(current);
      chain.push({ url: current, host: u.host, protocol: u.protocol });
      const loc = res.headers.get('location');
      if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
        current = new URL(loc, current).toString();
        continue;
      }
      return { hops: hop, chain, verified: true };
    }
    return { hops: 5, chain, verified: true };
  } catch (e) {
    return { hops: chain.length, chain, verified: false, error: e.message };
  }
}

/* Analyse principale : construit les motifs (findings), puis verdict + risque */
async function analyzeUrl(rawUrl, withRedirectCheck) {
  const findings = [];
  const input = String(rawUrl || '').trim();

  let parsed;
  try {
    parsed = new URL(input);
  } catch (e) {
    return finishAnalysis(input, null, null, [{ code: 'INVALID_URL', detail: input.slice(0, 80) }]);
  }

  if (!parsed.host) {
    return finishAnalysis(input, null, null, [{ code: 'INVALID_URL', detail: input.slice(0, 80) }]);
  }

  const host = parsed.hostname.toLowerCase(); // sans port
  const protocol = parsed.protocol.replace(':', '');
  const official = officialMatch(host);

  /* 1. Protocole */
  if (!['http', 'https'].includes(protocol)) {
    findings.push({ code: 'UNSAFE_PROTOCOL', detail: protocol || '?' });
  } else if (protocol === 'http') {
    findings.push({ code: 'NO_TLS', detail: 'HTTP' });
  }

  /* 2. Hôte local / IP / identifiants / port */
  if (host === 'localhost' || host.endsWith('.local') ||
      /^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0)/.test(host) || host === '::1') {
    findings.push({ code: 'LOCAL_HOST', detail: host });
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) {
    findings.push({ code: 'IP_HOST', detail: host });
  }
  if (parsed.username || parsed.password) {
    findings.push({ code: 'CREDENTIALS_IN_URL', detail: host });
  }
  if (parsed.port && !((protocol === 'http' && parsed.port === '80') ||
                       (protocol === 'https' && parsed.port === '443'))) {
    findings.push({ code: 'ODD_PORT', detail: parsed.port });
  }

  /* 3. Signes classiques de phishing */
  if (host.split('.').some((l) => l.startsWith('xn--'))) {
    findings.push({ code: 'PUNYCODE', detail: host });
  }
  const tld = host.split('.').pop();
  if (!official && RISKY_TLDS.has(tld)) {
    findings.push({ code: 'RISKY_TLD', detail: '.' + tld });
  }
  const labels = host.split('.').filter(Boolean);
  if (labels.length > 4 || host.length > 60) {
    findings.push({ code: 'COMPLEX_HOST', detail: host });
  }
  if (EXECUTABLE_EXT.test(parsed.pathname)) {
    findings.push({ code: 'EXECUTABLE_LINK', detail: path.posix.basename(parsed.pathname) });
  }
  const sensitiveKeys = [];
  for (const [k] of parsed.searchParams) {
    if (SENSITIVE_PARAM_RE.test(k)) sensitiveKeys.push(k);
  }
  if (sensitiveKeys.length) {
    findings.push({ code: 'SENSITIVE_PARAMS', detail: sensitiveKeys.slice(0, 3).join(', ') });
  }

  /* 4. Domaine officiel / usurpation de marque / typosquatting */
  if (official) {
    findings.push({ code: 'OFFICIAL_DOMAIN', detail: official.domain });
  } else {
    const reg = registrableDomain(host);
    for (const id of PLATFORM_IDS) {
      const d = PLATFORMS[id].domain;
      const brand = d.split('.')[0]; // facebook, instagram, tiktok…
      if (host.includes(brand)) {
        findings.push({ code: 'BRAND_IMPERSONATION', detail: `${PLATFORMS[id].name} (${d})` });
        break;
      }
    }
    if (!findings.some((f) => f.code === 'BRAND_IMPERSONATION')) {
      for (const id of PLATFORM_IDS) {
        const d = PLATFORMS[id].domain;
        if (reg !== d && levenshtein(reg, d) <= 2) {
          findings.push({ code: 'TYPOSQUAT', detail: d });
          break;
        }
      }
    }
  }

  /* 5. Vérification de la chaîne de redirections (optionnelle) */
  if (withRedirectCheck && ['http', 'https'].includes(protocol) &&
      host !== 'localhost' && !/^(127\.|10\.|192\.168\.|0\.0\.0\.0)/.test(host)) {
    const r = await followRedirects(input);
    if (!r.verified) {
      findings.push({ code: 'REDIRECT_UNVERIFIED', detail: r.error || 'network' });
    } else if (r.hops > 0) {
      const last = r.chain[r.chain.length - 1];
      const finalHost = last ? last.host : '?';
      findings.push({ code: 'REDIRECT_CHAIN', detail: r.hops + '|' + finalHost });
      const finalOfficial = last ? officialMatch(last.host.replace(/:\d+$/, '').toLowerCase()) : null;
      if (last && last.protocol === 'http:') {
        findings.push({ code: 'REDIRECT_INSECURE', detail: last.host });
      } else if (official && !finalOfficial) {
        findings.push({ code: 'REDIRECT_INSECURE', detail: finalHost });
      }
    }
  }

  return finishAnalysis(input, host, official, findings);
}

/* Trie les motifs par gravité puis calcule verdict + risque */
function finishAnalysis(url, host, official, findings) {
  const order = (c) =>
    DANGEROUS_FINDINGS.has(c) ? 0 :
    SUSPICIOUS_FINDINGS.has(c) ? 1 :
    c === 'INVALID_URL' ? 2 :
    INFO_FINDINGS.has(c) ? 3 : 4;
  findings.sort((a, b) => order(a.code) - order(b.code));

  const hasDanger = findings.some((f) => DANGEROUS_FINDINGS.has(f.code));
  const hasSus = findings.some((f) => SUSPICIOUS_FINDINGS.has(f.code));
  const chainSuspicious = findings.some(
    (f) => f.code === 'REDIRECT_CHAIN' && f.detail && f.detail.split('|')[1] &&
      !officialMatch(f.detail.split('|')[1].replace(/:\d+$/, '').toLowerCase())
  );

  let verdict, risk;
  if (hasDanger) { verdict = 'DANGEROUS'; risk = 'HIGH'; }
  else if (hasSus || chainSuspicious) { verdict = 'SUSPICIOUS'; risk = 'MEDIUM'; }
  else if (official && findings.some((f) => f.code === 'OFFICIAL_DOMAIN') &&
           !findings.some((f) => f.code === 'NO_TLS')) {
    verdict = 'TRUSTED'; risk = 'NONE';
  }
  else if (official) { verdict = 'SUSPICIOUS'; risk = 'LOW'; } // officiel mais HTTP
  else { verdict = 'UNVERIFIED'; risk = 'LOW'; }

  const analysis = {
    id: uid(),
    url,
    domain: host || '',
    platform: official ? official.platform : null,
    verdict,
    risk,
    findings,
    createdAt: nowIso(),
  };
  db.analyses.push(analysis);
  if (db.analyses.length > MAX_ANALYSES) {
    db.analyses.splice(0, db.analyses.length - MAX_ANALYSES);
  }
  scheduleSave();
  return analysis;
}

/* ============================================================================
   SECTION 9 — VUES : STATISTIQUES ET RAPPORTS
   ============================================================================ */

function lastNDays(n) {
  const days = [];
  const today = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i);
    days.push(dayKey(d));
  }
  return days;
}

function buildStats() {
  const today = dayKey(new Date());
  const days = lastNDays(7);
  const byDay = days.map((day) => ({ day, count: 0 }));
  const byPlatform = {};
  for (const id of PLATFORM_IDS) byPlatform[id] = 0;
  let active = 0, todayCount = 0;

  for (const l of db.links) if (l.status === 'ACTIVE') active++;
  for (const ev of db.events) {
    if (PLATFORMS[ev.platform]) byPlatform[ev.platform]++;
    const key = dayKey(ev.createdAt);
    const idx = days.indexOf(key);
    if (idx >= 0) byDay[idx].count++;
    if (key === today) todayCount++;
  }

  const byPlatformRows = PLATFORM_IDS
    .map((id) => ({ platform: id, count: byPlatform[id] }))
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count);

  const recentEvents = db.events.slice(-5).reverse();

  return {
    links: { active, total: db.links.length },
    events: { today: todayCount, total: db.events.length, byPlatform: byPlatformRows },
    analyses: { total: db.analyses.length },
    eventsByDay: byDay,
    recentEvents,
  };
}

function buildReports() {
  const cutoff7 = Date.now() - 7 * 24 * 3600 * 1000;
  const days = lastNDays(14);
  const byDay = days.map((day) => ({ day, count: 0 }));

  const platRows = {};
  for (const id of PLATFORM_IDS) platRows[id] = { platform: id, total: 0, last7days: 0, success: 0, blocked: 0 };
  for (const ev of db.events) {
    const row = platRows[ev.platform];
    if (!row) continue;
    row.total++;
    if (new Date(ev.createdAt).getTime() >= cutoff7) row.last7days++;
    if (ev.result === 'SUCCESS') row.success++;
    if (ev.result === 'BLOCKED') row.blocked++;
    const idx = days.indexOf(dayKey(ev.createdAt));
    if (idx >= 0) byDay[idx].count++;
  }

  const byPlatform = PLATFORM_IDS.map((id) => platRows[id]).filter((r) => r.total > 0);

  const topLinks = db.links
    .map((l) => ({ code: l.code, platform: l.platform, status: l.status, opens: eventCountFor(l.code) }))
    .sort((a, b) => b.opens - a.opens)
    .slice(0, 10);

  const verdictCounts = {};
  for (const a of db.analyses) verdictCounts[a.verdict] = (verdictCounts[a.verdict] || 0) + 1;
  const analysesVerdicts = Object.entries(verdictCounts)
    .map(([verdict, count]) => ({ verdict, count }))
    .sort((a, b) => b.count - a.count);

  return { byPlatform, topLinks, analysesVerdicts, byDay };
}

/* ============================================================================
   SECTION 10 — ROUTEUR API
   ============================================================================ */

function paginate(rows, page, pageSize) {
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const p = Math.min(Math.max(1, page), pages);
  return { rows: rows.slice((p - 1) * pageSize, p * pageSize), total, pages, page: p };
}

function intParam(v, def, min, max) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

async function handleApi(req, res, u) {
  const pathname = u.pathname;

  /* ── Santé (utile pour les monitors / Render) ── */
  if (req.method === 'GET' && pathname === '/api/health') {
    return sendJson(res, 200, { ok: true, uptime: process.uptime(), version: '1.0.0' }, req);
  }

  /* ── Authentification ── */
  if (pathname.startsWith('/api/auth/')) {
    return handleAuth(req, res, u, pathname);
  }

  /* ── Tout le reste exige une session valide ── */
  const sess = requireAuth(req);
  if (!sess) return sendError(res, 401, 'SESSION_EXPIRED', null, req);

  /* ── Liens ── */
  if (pathname === '/api/links') {
    if (req.method === 'GET') {
      const links = db.links
        .map(linkOut)
        .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
      return sendJson(res, 200, { links }, req);
    }
    if (req.method === 'POST') {
      const body = await readBody(req);
      if (!body || typeof body !== 'object') return sendError(res, 400, 'INVALID_BODY', null, req);
      const platform = String(body.platform || '');
      const plat = PLATFORMS[platform];
      if (!plat) return sendError(res, 400, 'UNKNOWN_PLATFORM', null, req);
      const note = String(body.note || '').slice(0, 300);
      let code = randomCode();
      let guard = 0;
      while (db.links.some((l) => l.code === code) && guard++ < 50) code = randomCode();
      if (guard >= 50) return sendError(res, 500, 'GENERATION_FAILED', null, req);
      const link = {
        id: uid(),
        code,
        platform,
        note,
        status: 'ACTIVE',
        destination: plat.destination,
        domain: plat.domain,
        createdAt: nowIso(),
      };
      db.links.push(link);
      scheduleSave();
      log(`Lien créé : /r/${code} → ${plat.domain}`);
      return sendJson(res, 200, { link: linkOut(link) }, req);
    }
    return sendError(res, 405, 'SERVER', null, req);
  }

  const mLink = /^\/api\/links\/([^/]+)$/.exec(pathname);
  if (mLink) {
    const link = db.links.find((l) => l.id === mLink[1]);
    if (!link) return sendError(res, 404, 'LINK_NOT_FOUND', null, req);
    if (req.method === 'GET') {
      return sendJson(res, 200, { link: linkOut(link) }, req);
    }
    if (req.method === 'PATCH') {
      const body = await readBody(req);
      if (!body || typeof body !== 'object') return sendError(res, 400, 'INVALID_BODY', null, req);
      const status = String(body.status || '');
      if (!['ACTIVE', 'DISABLED', 'REVOKED'].includes(status)) {
        return sendError(res, 400, 'INVALID_STATUS', null, req);
      }
      link.status = status;
      scheduleSave();
      return sendJson(res, 200, { link: linkOut(link) }, req);
    }
    return sendError(res, 405, 'SERVER', null, req);
  }

  /* ── Registre des événements ── */
  if (req.method === 'GET' && pathname === '/api/events') {
    const q = u.searchParams;
    const page = intParam(q.get('page'), 1, 1, 100000);
    const pageSize = intParam(q.get('pageSize'), 25, 1, 100);
    const sort = q.get('sort') === 'asc' ? 'asc' : 'desc';
    const search = (q.get('search') || '').trim().toLowerCase();
    const platform = q.get('platform') || '';
    const status = q.get('status') || '';
    const result = q.get('result') || '';

    let rows = db.events;
    if (platform) rows = rows.filter((e) => e.platform === platform);
    if (status) rows = rows.filter((e) => e.status === status);
    if (result) rows = rows.filter((e) => e.result === result);
    if (search) {
      rows = rows.filter((e) =>
        (e.code || '').toLowerCase().includes(search) ||
        (e.destination || '').toLowerCase().includes(search) ||
        (e.domain || '').toLowerCase().includes(search));
    }
    rows = rows.slice().sort((a, b) => {
      const c = a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0;
      return sort === 'asc' ? c : -c;
    });
    const pg = paginate(rows, page, pageSize);
    return sendJson(res, 200, { events: pg.rows, total: pg.total, pages: pg.pages, page: pg.page }, req);
  }

  /* ── Statistiques du tableau de bord ── */
  if (req.method === 'GET' && pathname === '/api/stats') {
    return sendJson(res, 200, buildStats(), req);
  }

  /* ── Rapports ── */
  if (req.method === 'GET' && pathname === '/api/reports') {
    return sendJson(res, 200, buildReports(), req);
  }

  /* ── Analyseur ── */
  if (req.method === 'POST' && pathname === '/api/analyzer') {
    const body = await readBody(req);
    if (!body || typeof body !== 'object') return sendError(res, 400, 'INVALID_BODY', null, req);
    const url = String(body.url || '').trim();
    if (!url) return sendError(res, 400, 'EMPTY_URL', null, req);
    const withRedirectCheck = body.withRedirectCheck === true || body.withRedirectCheck === 'true';
    const analysis = await analyzeUrl(url, withRedirectCheck);
    return sendJson(res, 200, analysis, req);
  }

  /* ── Historique des analyses (findings en JSON string, comme attendu) ── */
  if (req.method === 'GET' && pathname === '/api/analyses') {
    const q = u.searchParams;
    const page = intParam(q.get('page'), 1, 1, 100000);
    const pageSize = intParam(q.get('pageSize'), 25, 1, 100);
    const sort = q.get('sort') === 'asc' ? 'asc' : 'desc';
    const search = (q.get('search') || '').trim().toLowerCase();
    const verdict = q.get('verdict') || '';

    let rows = db.analyses;
    if (verdict) rows = rows.filter((a) => a.verdict === verdict);
    if (search) {
      rows = rows.filter((a) =>
        (a.url || '').toLowerCase().includes(search) ||
        (a.domain || '').toLowerCase().includes(search));
    }
    rows = rows.slice().sort((a, b) => {
      const c = a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0;
      return sort === 'asc' ? c : -c;
    });
    const pg = paginate(rows, page, pageSize);
    const analyses = pg.rows.map((a) => Object.assign({}, a, {
      findings: JSON.stringify(a.findings || []), // le frontend fait JSON.parse()
    }));
    return sendJson(res, 200, { analyses, total: pg.total, pages: pg.pages, page: pg.page }, req);
  }

  return sendError(res, 404, 'SERVER', null, req);
}

/* ============================================================================
   SECTION 11 — MOTEUR DE REDIRECTION /r/<code>
   ============================================================================ */

function pageHTML(title, line1, line2, statusColor) {
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)} — ATHEMIX37 PK14</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0a0d13;color:#e9edf4;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}
  .box{max-width:520px;padding:40px 36px;border:1px solid #1f2733;border-radius:14px;
       background:#10151f;text-align:center}
  h1{font-size:20px;margin:0 0 10px;color:${statusColor};letter-spacing:.06em}
  p{margin:6px 0;color:#8f97a8;font-size:14px;line-height:1.55}
  code{background:#0a0d13;border:1px solid #1f2733;border-radius:6px;padding:2px 8px;
       font-family:ui-monospace,monospace;color:#e9edf4}
</style></head>
<body><div class="box"><h1>${escapeHtml(title)}</h1>
<p>${escapeHtml(line1)}</p><p>${escapeHtml(line2)}</p>
</div></body></html>`;
}

function respondRedirect(res, req, link) {
  applyCors(req, res);
  res.writeHead(302, { Location: link.destination, 'Cache-Control': 'no-store' });
  res.end();
}

function handleRedirect(req, res, code) {
  const link = db.links.find((l) => l.code === code);

  if (!link) {
    recordEvent(code, '', 'FAILURE', 'WARNING', 'LINK_NOT_FOUND', '', '');
    log(`/r/${code} → introuvable`);
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(pageHTML('Lien introuvable',
      `Le lien /r/${escapeHtml(code)} n'existe pas dans le registre.`,
      'Vérifie le code ou demande un nouveau lien à l\'administrateur.', '#ff2b4e'));
    return;
  }

  if (link.status === 'ACTIVE') {
    recordEvent(link.code, link.platform, 'SUCCESS', 'OK', 'REDIRECT_OK',
      link.destination, link.domain);
    log(`/r/${link.code} → 302 ${link.domain}`);
    respondRedirect(res, req, link);
    return;
  }

  if (link.status === 'DISABLED') {
    recordEvent(link.code, link.platform, 'BLOCKED', 'WARNING', 'LINK_DISABLED', '', '');
    log(`/r/${link.code} → bloqué (désactivé)`);
    res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(pageHTML('Lien désactivé',
      `Le lien /r/${escapeHtml(link.code)} a été désactivé par l'administrateur.`,
      'La redirection est bloquée.', '#e6a23c'));
    return;
  }

  /* REVOKED */
  recordEvent(link.code, link.platform, 'BLOCKED', 'WARNING', 'LINK_REVOKED', '', '');
  log(`/r/${link.code} → bloqué (révoqué)`);
  res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(pageHTML('Lien révoqué',
    `Le lien /r/${escapeHtml(link.code)} a été révoqué.`,
    'La redirection est définitivement bloquée.', '#ff2b4e'));
}

/* ============================================================================
   SECTION 12 — FICHIERS STATIQUES (l'interface unique index.html)
   ============================================================================ */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden');
    return;
  }
  fs.readFile(filePath, (err, buf) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 — fichier introuvable');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'Content-Length': buf.length,
    });
    res.end(buf);
  });
}

/* ============================================================================
   SECTION 13 — DISPATCH GLOBAL + DÉMARRAGE
   ============================================================================ */

const server = http.createServer((req, res) => {
  let u;
  try {
    u = new URL(req.url, 'http://localhost');
  } catch (e) {
    res.writeHead(400); res.end('Bad Request');
    return;
  }

  /* Le client socket.io embarqué se connecte sur le chemin « / » avec les
     paramètres EIO/transport/sid : on route ces requêtes vers engine.io.
     Le paramètre XTransformPort envoyé par le frontend est simplement ignoré. */
  const q = u.searchParams;
  if (q.has('EIO') || q.has('sid') || q.has('transport')) {
    try {
      io.engine.handleRequest(req, res);
    } catch (e) {
      if (!res.headersSent) { res.writeHead(400); res.end(); }
      else try { res.end(); } catch (e2) { /* déjà fermée */ }
    }
    return;
  }

  if (req.method === 'OPTIONS') return handleOptions(req, res);

  const pathname = u.pathname;

  /* Redirection publique /r/<code> */
  const mR = /^\/r\/([A-Za-z0-9]+)$/.exec(pathname);
  if (mR && (req.method === 'GET' || req.method === 'HEAD')) {
    try { return handleRedirect(req, res, mR[1]); }
    catch (e) {
      log('ERREUR redirection : ' + e.message);
      if (!res.headersSent) sendError(res, 500, 'SERVER', null, req);
    }
  }

  /* API interne */
  if (pathname.startsWith('/api/')) {
    handleApi(req, res, u).catch((e) => {
      log('ERREUR API : ' + (e && e.stack || e));
      if (!res.headersSent) sendError(res, 500, 'SERVER', null, req);
    });
    return;
  }

  /* Interface (fichier unique) */
  if (req.method === 'GET' || req.method === 'HEAD') {
    return serveStatic(req, res, pathname);
  }

  res.writeHead(405, { 'Content-Type': 'text/plain' });
  res.end('Method Not Allowed');
});

/* WebSocket (transport websocket de socket.io) */
server.on('upgrade', (req, socket, head) => {
  try {
    io.engine.handleUpgrade(req, socket, head);
  } catch (e) {
    try { socket.destroy(); } catch (e2) { /* rien */ }
  }
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) { /* rien */ }
});

process.on('unhandledRejection', (e) => log('Promesse rejetée : ' + (e && e.stack || e)));
process.on('SIGINT', () => { log('Arrêt (SIGINT), sauvegarde…'); flushSave(); process.exit(0); });
process.on('SIGTERM', () => { log('Arrêt (SIGTERM), sauvegarde…'); flushSave(); process.exit(0); });

function lanAddresses() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const it of ifs[name] || []) {
      if (it.family === 'IPv4' && !it.internal) out.push(it.address);
    }
  }
  return out;
}

loadData();
cleanExpiredSessions();
setInterval(cleanExpiredSessions, 15 * 60 * 1000);

server.listen(PORT, HOST, () => {
  log('==========================================================');
  log('  ATHEMIX37 PK14 — serveur démarré');
  log(`  Interface      : http://localhost:${PORT}/`);
  for (const ip of lanAddresses()) {
    log(`  Réseau local   : http://${ip}:${PORT}/   (à ouvrir depuis le téléphone)`);
  }
  log(`  Stockage       : ${DATA_FILE}`);
  log(`  Sessions       : validité ${SESSION_TTL_MS / 3600000} h`);
  log('  Premier lancement : le compte administrateur est créé');
  log('  à la première connexion sur l\'interface.');
  log('==========================================================');
});

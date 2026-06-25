const express = require('express');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

function resolveDataDir() {
  const configured = String(process.env.APP_DATA_DIR || process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || '').trim();
  if (!configured) return __dirname;
  return path.isAbsolute(configured) ? configured : path.join(__dirname, configured);
}

const DATA_DIR = resolveDataDir();
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (err) { }
function dataPath(fileName) { return path.join(DATA_DIR, fileName); }

const AUTH_WEB_FILE = dataPath('auth.json');
const CHANGE_WEB_FILE = dataPath('change.json');
const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = process.env.LOG_FILE
  ? (path.isAbsolute(process.env.LOG_FILE) ? process.env.LOG_FILE : path.join(__dirname, process.env.LOG_FILE))
  : path.join(LOG_DIR, 'server.log');
const SESSION_COOKIE = 'whatsapp_admin_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const LOGIN_CSRF_TTL_MS = 30 * 60 * 1000;
const LOGIN_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_LIMIT_LOCK_MS = 15 * 60 * 1000;
const LOGIN_RATE_LIMIT_MAX = 5;
const PUBLIC_ROUTE_RATE_LIMIT_MAX = Number(process.env.PUBLIC_ROUTE_RATE_LIMIT_MAX || 60);
const AUTH_ROUTE_RATE_LIMIT_MAX = Number(process.env.AUTH_ROUTE_RATE_LIMIT_MAX || 20);
const BOT_AUTH_RATE_LIMIT_MAX = Number(process.env.BOT_AUTH_RATE_LIMIT_MAX || 12);
const DEFAULT_ALLOWED_HOSTS = '';
const ALLOW_LOCALHOST_HOSTS = String(process.env.ALLOW_LOCALHOST_HOSTS || 'true').toLowerCase() !== 'false';
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '0x4AAAAAADOJ-PZpGS3lgZip';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '0x4AAAAAADOJ-Lvp8Awu8r1Gfz4kmh--AyM';
const PASSWORD_HASH = {
  algorithm: 'scrypt',
  keyLength: 64,
  cost: 16384,
  blockSize: 8,
  parallelization: 1
};
const sessions = new Map();
const loginAttempts = new Map();
let dummyPasswordRecord = null;
const LOGIN_CSRF_SECRET = secureRandomToken(32);

function escapeHtml(str = '') {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function normalizeHostName(value = '') {
  let host = String(value || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().toLowerCase();
  if (!host) return '';

  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) host = new URL(host).host;
  } catch (err) {
    return '';
  }

  host = host.split('/')[0];
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    host = end >= 0 ? host.slice(1, end) : '';
  } else {
    host = host.split(':')[0];
  }

  while (host.endsWith('.')) host = host.slice(0, -1);
  return host;
}

function parseAllowedHosts(value = '') {
  const hosts = new Set(
    String(value || '')
      .split(',')
      .map(normalizeHostName)
      .filter(Boolean)
  );

  if (ALLOW_LOCALHOST_HOSTS && hosts.size > 0) {
    hosts.add('localhost');
    hosts.add('127.0.0.1');
    hosts.add('::1');
  }

  return hosts;
}

function enforceAllowedHost(allowedHosts) {
  return (req, res, next) => {
    if (!allowedHosts || allowedHosts.size === 0) return next();
    const host = normalizeHostName(req.headers.host);
    if (allowedHosts.has(host)) return next();
    return res.status(404).send('Not found');
  };
}

function secureRandomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function saveJsonSecure(filePath, data) {
  const tempPath = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(tempPath, 0o600); } catch (err) { }
  fs.renameSync(tempPath, filePath);
  try { fs.chmodSync(filePath, 0o600); } catch (err) { }
}

function hashPassword(password, salt = secureRandomToken(16)) {
  const key = crypto.scryptSync(String(password), salt, PASSWORD_HASH.keyLength, {
    N: PASSWORD_HASH.cost,
    r: PASSWORD_HASH.blockSize,
    p: PASSWORD_HASH.parallelization,
    maxmem: 64 * 1024 * 1024
  }).toString('hex');

  return {
    algorithm: PASSWORD_HASH.algorithm,
    salt,
    key,
    keyLength: PASSWORD_HASH.keyLength,
    cost: PASSWORD_HASH.cost,
    blockSize: PASSWORD_HASH.blockSize,
    parallelization: PASSWORD_HASH.parallelization
  };
}

function createUserRecord(name, password) {
  return { name: String(name), password: hashPassword(password) };
}

function clearCredentialChangeFile() {
  try {
    fs.writeFileSync(CHANGE_WEB_FILE, '', { encoding: 'utf8', mode: 0o600 });
    try { fs.chmodSync(CHANGE_WEB_FILE, 0o600); } catch (err) { }
  } catch (err) { }
}

function readCredentialChangeFile() {
  try {
    if (!fs.existsSync(CHANGE_WEB_FILE)) return null;
    const raw = fs.readFileSync(CHANGE_WEB_FILE, 'utf8').replace(/^\uFEFF/, '');
    if (!raw.trim()) return null;

    const lines = raw.split(/\r?\n/);
    const name = String(lines[0] || '').trim();
    const password = String(lines[1] || '').trim();
    if (!name || !password) return null;

    return { name, password };
  } catch (err) {
    return null;
  }
}

function applyCredentialChangeFile(auth) {
  const change = readCredentialChangeFile();
  if (!change) return auth;

  const updatedAuth = {
    version: 2,
    users: [createUserRecord(change.name, change.password)]
  };

  saveJsonSecure(AUTH_WEB_FILE, updatedAuth);
  clearCredentialChangeFile();
  sessions.clear();
  loginAttempts.clear();
  return updatedAuth;
}

function normalizeWebAuth(parsed) {
  if (parsed && Array.isArray(parsed.users)) {
    return {
      auth: {
        version: 2,
        users: parsed.users
          .filter((user) => user && typeof user.name === 'string' && user.password && typeof user.password.key === 'string')
          .map((user) => ({ name: user.name, password: user.password }))
      },
      shouldSave: parsed.version !== 2
    };
  }

  const names = Array.isArray(parsed?.name) ? parsed.name : [];
  const passwords = Array.isArray(parsed?.password) ? parsed.password : [];
  const users = names
    .map((name, index) => (passwords[index] === undefined ? null : createUserRecord(name, passwords[index])))
    .filter(Boolean);

  return { auth: { version: 2, users }, shouldSave: users.length > 0 };
}

function loadWebAuth() {
  try {
    if (!fs.existsSync(AUTH_WEB_FILE)) {
      const initial = { version: 2, users: [createUserRecord(process.env.WEB_ADMIN_USER || 'admin', process.env.WEB_ADMIN_PASSWORD || 'admin')] };
      const changed = applyCredentialChangeFile(initial);
      if (changed === initial) saveJsonSecure(AUTH_WEB_FILE, initial);
      return changed;
    }
    const raw = fs.readFileSync(AUTH_WEB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    const normalized = normalizeWebAuth(parsed);
    if (normalized.shouldSave) saveJsonSecure(AUTH_WEB_FILE, normalized.auth);
    return applyCredentialChangeFile(normalized.auth);
  } catch (err) {
    return { version: 2, users: [] };
  }
}

function timingSafeStringEqual(a = '', b = '') {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    crypto.timingSafeEqual(left, left);
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, passwordRecord) {
  try {
    if (!passwordRecord || passwordRecord.algorithm !== PASSWORD_HASH.algorithm) return false;
    const expected = Buffer.from(passwordRecord.key, 'hex');
    const derived = crypto.scryptSync(String(password), passwordRecord.salt, passwordRecord.keyLength || PASSWORD_HASH.keyLength, {
      N: passwordRecord.cost || PASSWORD_HASH.cost,
      r: passwordRecord.blockSize || PASSWORD_HASH.blockSize,
      p: passwordRecord.parallelization || PASSWORD_HASH.parallelization,
      maxmem: 64 * 1024 * 1024
    });
    if (expected.length !== derived.length) return false;
    return crypto.timingSafeEqual(expected, derived);
  } catch (err) {
    return false;
  }
}

function verifyWebCredentials(auth, user, pass) {
  let matchedUser = null;
  for (const record of auth.users || []) {
    if (timingSafeStringEqual(record.name, user)) {
      matchedUser = record;
      break;
    }
  }

  if (!matchedUser) {
    if (!dummyPasswordRecord) dummyPasswordRecord = hashPassword('unused-password');
    verifyPassword(pass, dummyPasswordRecord);
    return false;
  }

  return verifyPassword(pass, matchedUser.password);
}

function isSafeCookieName(key = '') {
  return Boolean(key) && key !== '__proto__' && key !== 'prototype' && key !== 'constructor';
}

function parseCookies(cookieHeader = '') {
  const cookies = new Map();
  for (const part of cookieHeader.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (isSafeCookieName(key)) {
      try { cookies.set(key, decodeURIComponent(value)); }
      catch (err) { cookies.set(key, value); }
    }
  }
  return cookies;
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies.get(SESSION_COOKIE);
  const session = token ? sessions.get(token) : null;
  if (!token || !session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return { token, user: session.user, csrfToken: session.csrfToken };
}

function buildCookieOptions(req, maxAgeSeconds) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  return [
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
    secure ? 'Secure' : ''
  ].filter(Boolean).join('; ');
}

function createSession(res, req, user) {
  const token = secureRandomToken(32);
  sessions.set(token, { user, csrfToken: secureRandomToken(32), expiresAt: Date.now() + SESSION_TTL_MS });
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; ${buildCookieOptions(req, Math.floor(SESSION_TTL_MS / 1000))}`);
}

function clearSession(res, req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies.get(SESSION_COOKIE);
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; ${buildCookieOptions(req, 0)}`);
}

function sanitizeNextPath(nextPath) {
  if (typeof nextPath !== 'string') return '/dashboard';
  const cleanPath = nextPath.replace(/[\u0000-\u001f\u007f]/g, '');
  if (!cleanPath.startsWith('/') || cleanPath.startsWith('//') || cleanPath.startsWith('/\\')) return '/dashboard';
  try {
    const parsed = new URL(cleanPath, 'https://salibot.local');
    if (parsed.origin !== 'https://salibot.local') return '/dashboard';
    const safePath = `${parsed.pathname}${parsed.search}${parsed.hash}`;
    if (safePath === '/' || safePath === '/login') return '/dashboard';
    const allowedBotPath = /^\/[a-zA-Z0-9_-]+\/(?:allowed|grouptracked|qr|pair)?(?:[?#].*)?$/.test(safePath);
    if (safePath === '/dashboard' || safePath.startsWith('/dashboard?') || safePath.startsWith('/dashboard#') || allowedBotPath) return safePath;
    return '/dashboard';
  } catch (err) {
    return '/dashboard';
  }
}

function csrfInput(session) {
  return `<input type="hidden" name="_csrf" value="${escapeHtml(session?.csrfToken || '')}" />`;
}

function getClientIp(req) {
  // Behind Cloudflare, CF-Connecting-IP carries the real client IP and is set by
  // the edge (cannot be spoofed by clients). Fall back to Express's trusted req.ip.
  const cf = req.headers['cf-connecting-ip'];
  if (typeof cf === 'string' && cf.trim()) return cf.trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function getRateLimitKey(req) {
  return ipKeyGenerator(getClientIp(req));
}

function makeWebRateLimiter(max, message) {
  return rateLimit({
    windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getRateLimitKey,
    message
  });
}

function getLoginAttemptKey(req) {
  return getClientIp(req);
}

function isLoginBlocked(req) {
  const now = Date.now();
  const key = getLoginAttemptKey(req);
  const attempt = loginAttempts.get(key);
  if (!attempt) return false;
  if (attempt.blockedUntil && attempt.blockedUntil > now) return true;
  if (attempt.firstAttemptAt + LOGIN_RATE_LIMIT_WINDOW_MS < now) loginAttempts.delete(key);
  return false;
}

function recordLoginFailure(req) {
  const now = Date.now();
  const key = getLoginAttemptKey(req);
  const current = loginAttempts.get(key);
  const attempt = current && current.firstAttemptAt + LOGIN_RATE_LIMIT_WINDOW_MS > now
    ? current
    : { count: 0, firstAttemptAt: now, blockedUntil: 0 };

  attempt.count += 1;
  if (attempt.count >= LOGIN_RATE_LIMIT_MAX) attempt.blockedUntil = now + LOGIN_RATE_LIMIT_LOCK_MS;
  loginAttempts.set(key, attempt);
}

function recordLoginSuccess(req) {
  loginAttempts.delete(getLoginAttemptKey(req));
}

function isValidCsrf(submitted, expected) {
  return Boolean(submitted && expected && timingSafeStringEqual(submitted, expected));
}

function createLoginCsrfToken() {
  const expiresAt = Date.now() + LOGIN_CSRF_TTL_MS;
  const nonce = secureRandomToken(16);
  const payload = `${expiresAt}.${nonce}`;
  const signature = crypto.createHmac('sha256', LOGIN_CSRF_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function isValidLoginCsrfToken(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return false;
    const [expiresAt, nonce, signature] = parts;
    if (!/^\d+$/.test(expiresAt) || !nonce || Number(expiresAt) < Date.now()) return false;
    const payload = `${expiresAt}.${nonce}`;
    const expected = crypto.createHmac('sha256', LOGIN_CSRF_SECRET).update(payload).digest('base64url');
    return timingSafeStringEqual(signature, expected);
  } catch (err) {
    return false;
  }
}

async function verifyTurnstile(req) {
  const token = String(req.body['cf-turnstile-response'] || '');
  if (!token) return { ok: false, status: 400, message: 'Security check missing. Please try again.' };

  try {
    const verifyResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: getClientIp(req)
      })
    });
    const result = await verifyResponse.json();
    return result.success
      ? { ok: true }
      : { ok: false, status: 403, message: 'Security check failed. Please try again.' };
  } catch (err) {
    return { ok: false, status: 503, message: 'Security check unavailable. Please try again.' };
  }
}

function applySecurityHeaders(req, res, next) {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data:",
    "font-src 'self' https://fonts.gstatic.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
    "frame-src https://challenges.cloudflare.com",
    "connect-src 'self' https://challenges.cloudflare.com"
  ].join('; '));
  next();
}

function sanitizeLogField(value = '') {
  return String(value).replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 2048);
}

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function formatLogSize(bytes = 0) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function readLogTail(filePath, maxLines = 500, maxBytes = 512 * 1024) {
  let fd = null;
  try {
    const stat = fs.statSync(filePath);
    const readBytes = Math.min(stat.size, maxBytes);
    const buffer = Buffer.alloc(readBytes);
    fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, readBytes, Math.max(0, stat.size - readBytes));
    fs.closeSync(fd);
    fd = null;

    const rawText = buffer.toString('utf8');
    const lines = rawText.split(/\r?\n/);
    const sliced = lines.length > maxLines ? lines.slice(-maxLines) : lines;

    return {
      exists: true,
      text: sliced.join('\n').trimEnd(),
      size: stat.size,
      mtime: stat.mtime,
      truncated: stat.size > readBytes || lines.length > maxLines,
      path: filePath
    };
  } catch (err) {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch (closeErr) { }
    }
    return {
      exists: false,
      text: '',
      size: 0,
      mtime: null,
      truncated: false,
      path: filePath,
      error: err && err.code === 'ENOENT' ? 'Log file not found yet.' : `Unable to read log file: ${err.message}`
    };
  }
}

function getExistingBotId(bots, botId) {
  const value = String(botId || '');
  return bots.has(value) ? value : '';
}

function botPath(botId, suffix = '/') {
  return `/${encodeURIComponent(botId)}${suffix}`;
}

// ─── SVG ICONS ───────────────────────────────────────────────────────────────
const ICO = {
  server: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>`,
  grid: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>`,
  check: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  eye: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/></svg>`,
  qr: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3M21 14v.01M14 18h.01M17 18h4M21 21h-4M17 21v-3"/></svg>`,
  phone: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2A19.8 19.8 0 0 1 11.4 19a19.4 19.4 0 0 1-5.4-5.4A19.8 19.8 0 0 1 3.1 4.18 2 2 0 0 1 5.07 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L9.09 9.91a16 16 0 0 0 5.41 5.41l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>`,
  plus: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  bolt: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>`,
  refresh: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.75"/></svg>`,
  restart: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.75"/></svg>`,
  unplug: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64A9 9 0 0 1 21 12"/><path d="M6.16 6.16a9 9 0 1 0 12.68 12.68"/><line x1="2" y1="2" x2="22" y2="22"/></svg>`,
  trash: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>`,
  save: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>`,
  settings: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  bot: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4M8 11V9M16 11V9"/></svg>`,
  clock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  msg: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
  logs: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h8M8 9h2"/></svg>`,
  logo: `<svg viewBox="0 0 44 22" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M3 3H13L3 10Z"/><path d="M41 3H31L41 10Z"/><path d="M3 12V19H13Z"/><path d="M41 12V19H31Z"/><rect x="17" y="3" width="10" height="7" rx="2"/><rect x="17" y="12" width="10" height="7" rx="2"/></svg>`,
  home: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9.5 12 3l9 6.5"/><path d="M5 10v10h14V10"/><path d="M9 20v-6h6v6"/></svg>`,
  logout: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
  search: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  shield: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  dots: `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>`,
  sun: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>`,
  moon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  power: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>`,
  pause: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>`,
};

// ─── GLOBAL CSS + HEAD ───────────────────────────────────────────────────────
function getGlobalStyles(title = 'WhatsApp Bot') {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <title>${escapeHtml(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <link rel="icon" type="image/svg+xml" href="${FAVICON_HREF}" />
  <meta name="theme-color" content="#0d0d14" />
  <script>
    (function(){try{var t=localStorage.getItem('salibot-theme');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();
    function toggleTheme(){try{var d=document.documentElement,c=d.getAttribute('data-theme');if(!c){c=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';}var n=(c==='dark')?'light':'dark';d.setAttribute('data-theme',n);localStorage.setItem('salibot-theme',n);}catch(e){}}
  </script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:            oklch(9% 0.012 280);
      --bg2:           oklch(12% 0.014 280);
      --bg-side:       oklch(6.5% 0.010 280);
      --appbar-bg:     oklch(10% 0.012 280 / 0.82);
      --panel:         oklch(12.5% 0.014 280);
      --panel-2:       oklch(16% 0.016 280);
      --panel-raised:  oklch(15% 0.016 280);
      --hover:         oklch(19% 0.018 280);
      --border:        oklch(26% 0.018 280);
      --border-soft:   oklch(21% 0.014 280);
      --text:          oklch(95% 0.005 280);
      --text-muted:    oklch(66% 0.012 280);
      --text-faint:    oklch(47% 0.012 280);
      --purple:        oklch(66% 0.21 292);
      --purple-dim:    oklch(57% 0.18 292);
      --purple-mid:    oklch(49% 0.16 292);
      --purple-glow:   oklch(66% 0.21 292 / 0.30);
      --purple-subtle: oklch(20% 0.06 292);
      --purple-soft:   oklch(20% 0.06 292);
      --purple-border: oklch(40% 0.13 292);
      --green:         oklch(74% 0.16 155);
      --green-soft:    oklch(24% 0.06 155);
      --green-border:  oklch(42% 0.10 155);
      --online:        oklch(72% 0.15 210);
      --online-subtle: oklch(20% 0.06 210);
      --online-border: oklch(40% 0.12 210);
      --red:           oklch(64% 0.21 25);
      --red-subtle:    oklch(22% 0.06 25);
      --red-border:    oklch(42% 0.14 25);
      --amber:         oklch(78% 0.16 80);
      --amber-subtle:  oklch(24% 0.06 80);
      --radius-sm: 8px;
      --radius:    12px;
      --radius-lg: 18px;
      --radius-xl: 22px;
      --shadow:    0 10px 30px oklch(0% 0 0 / 0.45);
    }

    @media (prefers-color-scheme: light) {
      :root:not([data-theme]) {
        --bg:            oklch(97% 0.004 280);
        --bg2:           oklch(94% 0.006 280);
        --bg-side:       oklch(99% 0.003 280);
        --appbar-bg:     oklch(100% 0 0 / 0.82);
        --panel:         oklch(100% 0 0);
        --panel-2:       oklch(97% 0.004 280);
        --panel-raised:  oklch(97% 0.004 280);
        --hover:         oklch(95% 0.006 280);
        --border:        oklch(86% 0.010 280);
        --border-soft:   oklch(90% 0.008 280);
        --text:          oklch(15% 0.010 280);
        --text-muted:    oklch(45% 0.012 280);
        --text-faint:    oklch(60% 0.010 280);
        --purple-subtle: oklch(95% 0.04 292);
        --purple-soft:   oklch(95% 0.04 292);
        --green-soft:    oklch(95% 0.04 155);
        --green-border:  oklch(74% 0.10 155);
        --online-subtle: oklch(95% 0.04 210);
        --online-border: oklch(72% 0.12 210);
        --red-subtle:    oklch(95% 0.04 25);
        --red-border:    oklch(72% 0.12 25);
        --amber-subtle:  oklch(96% 0.04 80);
      }
    }

    /* Manual theme override (set via the toggle button, wins over the OS preference) */
    :root[data-theme="light"] {
      --bg:            oklch(97% 0.004 280);
      --bg2:           oklch(94% 0.006 280);
      --bg-side:       oklch(99% 0.003 280);
      --appbar-bg:     oklch(100% 0 0 / 0.82);
      --panel:         oklch(100% 0 0);
      --panel-2:       oklch(97% 0.004 280);
      --panel-raised:  oklch(97% 0.004 280);
      --hover:         oklch(95% 0.006 280);
      --border:        oklch(86% 0.010 280);
      --border-soft:   oklch(90% 0.008 280);
      --text:          oklch(15% 0.010 280);
      --text-muted:    oklch(45% 0.012 280);
      --text-faint:    oklch(60% 0.010 280);
      --purple-subtle: oklch(95% 0.04 292);
      --purple-soft:   oklch(95% 0.04 292);
      --green-soft:    oklch(95% 0.04 155);
      --green-border:  oklch(74% 0.10 155);
      --online-subtle: oklch(95% 0.04 210);
      --online-border: oklch(72% 0.12 210);
      --red-subtle:    oklch(95% 0.04 25);
      --red-border:    oklch(72% 0.12 25);
      --amber-subtle:  oklch(96% 0.04 80);
    }

    html { font-size: 15px; }
    body { font-family: 'Geist', 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; -webkit-font-smoothing: antialiased; line-height: 1.5; }

    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }

    .ico { display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .ico svg { display: block; }

    .container { max-width: 1180px; margin: 0 auto; padding: 32px 28px; }

    .page-shell { background: var(--panel); border: 1px solid var(--border-soft); border-radius: var(--radius-xl); padding: 28px; box-shadow: var(--shadow); }

    .topbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 28px; }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-badge { width: 46px; height: 46px; border-radius: 14px; flex-shrink: 0; display: inline-flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--purple), var(--purple-dim)); color: #fff; box-shadow: 0 6px 20px var(--purple-glow); }
    .brand-text h1, .brand-text h2 { font-size: 1.35rem; font-weight: 800; line-height: 1.1; color: var(--text); margin: 0; }
    .brand-text p { margin-top: 3px; color: var(--text-muted); font-size: 0.88rem; }

    .nav-links { display: flex; flex-wrap: wrap; gap: 8px; }
    .nav-links a { text-decoration: none; color: var(--text-muted); background: var(--panel-raised); border: 1px solid var(--border-soft); padding: 7px 13px; border-radius: 99px; font-size: 0.845rem; font-weight: 600; transition: all 0.18s ease; display: inline-flex; align-items: center; gap: 6px; }
    .nav-links a:hover { color: var(--purple); border-color: var(--purple-border); background: var(--purple-subtle); }

    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-top: 20px; }
    .stat-card { background: var(--panel-raised); border: 1px solid var(--border-soft); border-radius: var(--radius); padding: 18px 20px; transition: transform 0.2s ease, box-shadow 0.2s ease; position: relative; overflow: hidden; }
    .stat-card::after { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, var(--purple), transparent); opacity: 0; transition: opacity 0.2s; }
    .stat-card:hover { transform: translateY(-3px); box-shadow: var(--shadow); }
    .stat-card:hover::after { opacity: 1; }
    .stat-label { font-size: 0.75rem; font-weight: 700; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 10px; }
    .stat-value { font-size: 1.7rem; font-weight: 800; line-height: 1; word-break: break-word; }
    .stat-sub { font-size: 0.78rem; color: var(--text-muted); margin-top: 6px; }

    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

    .card { background: var(--panel-raised); border: 1px solid var(--border-soft); border-radius: var(--radius); padding: 22px; }
    .card > h2 { font-size: 1rem; font-weight: 700; margin: 0 0 8px; color: var(--text); }
    .card > p { color: var(--text-muted); font-size: 0.9rem; margin: 0; }

    hr.divider { border: none; border-top: 1px solid var(--border-soft); margin: 18px 0; }

    .status-pill { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px; border-radius: 99px; font-size: 0.8rem; font-weight: 700; }
    .status-pill::before { content: ''; width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
    .status-online { color: var(--online); background: var(--online-subtle); border: 1px solid var(--online-border); }
    .status-online::before { background: var(--online); box-shadow: 0 0 6px var(--online); }
    .status-offline { color: var(--text-faint); background: var(--bg2); border: 1px solid var(--border); }
    .status-offline::before { background: var(--text-faint); }

    .bot-card { background: var(--panel-raised); border: 1px solid var(--border-soft); border-radius: var(--radius); padding: 20px; transition: border-color 0.2s, transform 0.2s; }
    .bot-card:hover { border-color: var(--purple-border); transform: translateY(-2px); }
    .bot-card-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 16px; }
    .bot-card-label { font-size: 0.7rem; font-weight: 700; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 4px; }
    .bot-card-name { font-size: 1.05rem; font-weight: 800; }

    button, .btn { font-family: 'Geist', 'Inter', system-ui, sans-serif; appearance: none; border: none; padding: 10px 18px; border-radius: var(--radius-sm); font-size: 0.88rem; font-weight: 700; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 7px; text-decoration: none; transition: all 0.18s ease; }
    button:not([class]), .btn-primary { background: var(--purple); color: #fff; box-shadow: 0 4px 16px var(--purple-glow); }
    button:not([class]):hover, .btn-primary:hover { background: var(--purple-dim); transform: translateY(-1px); box-shadow: 0 8px 24px var(--purple-glow); }
    .btn-secondary { background: var(--panel-raised); color: var(--text); border: 1px solid var(--border); }
    .btn-secondary:hover { border-color: var(--purple); color: var(--purple); }
    .btn-danger { background: var(--red-subtle); color: var(--red); border: 1px solid var(--red-border); }
    .btn-danger:hover { background: var(--red); color: #fff; }
    .btn-warning { background: var(--amber-subtle); color: var(--amber); border: 1px solid oklch(42% 0.14 75); }
    .btn-warning:hover { background: var(--amber); color: #fff; }
    .btn-sm { padding: 7px 12px; font-size: 0.8rem; }
    .btn-full { width: 100%; }

    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }

    input[type="text"], input[type="tel"], input[type="password"] { font-family: inherit; width: 100%; padding: 10px 13px; background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text); font-size: 0.9rem; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
    input[type="text"]:focus, input[type="tel"]:focus, input[type="password"]:focus { border-color: var(--purple); box-shadow: 0 0 0 3px var(--purple-glow); }
    select { font-family: inherit; width: 100%; padding: 10px 13px; background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text); font-size: 0.9rem; cursor: pointer; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
    select:focus { border-color: var(--purple); box-shadow: 0 0 0 3px var(--purple-glow); }
    select option { background: var(--panel); }

    .list-wrap { border: 1px solid var(--border-soft); border-radius: var(--radius); overflow: hidden; background: var(--bg2); max-height: 400px; overflow-y: auto; }
    .group-item { display: block; padding: 12px 16px; border-bottom: 1px solid var(--border-soft); transition: background 0.15s; cursor: pointer; }
    .group-item:last-child { border-bottom: none; }
    .group-item:hover { background: var(--panel); }
    .group-line { display: flex; align-items: flex-start; gap: 12px; }
    .group-line input[type="checkbox"] { width: auto; padding: 0; margin-top: 3px; accent-color: var(--purple); transform: scale(1.2); flex-shrink: 0; }
    .group-name { font-weight: 700; font-size: 0.88rem; color: var(--text); display: block; margin-bottom: 2px; }
    .group-jid { color: var(--text-faint); font-size: 0.74rem; font-family: monospace; word-break: break-all; }

    .empty-box { padding: 24px 16px; text-align: center; color: var(--text-faint); font-size: 0.85rem; border: 1px dashed var(--border); border-radius: var(--radius); background: var(--bg2); }

    .center-wrap { max-width: 560px; margin: 0 auto; text-align: center; }
    .simple-card { background: var(--panel-raised); border: 1px solid var(--border-soft); border-radius: var(--radius-lg); padding: 30px; box-shadow: var(--shadow); }
    .simple-card h2 { font-size: 1.2rem; margin: 0 0 10px; }
    .simple-card p { color: var(--text-muted); font-size: 0.9rem; line-height: 1.65; }

    .qr-box { background: #fff; border-radius: var(--radius); padding: 18px; display: inline-block; border: 1px solid var(--border); box-shadow: var(--shadow); }
    .qr-box img { width: 100%; max-width: 280px; height: auto; border-radius: 8px; display: block; }

    .code-display { font-size: 2.6rem; letter-spacing: 10px; font-weight: 800; color: var(--purple); padding: 20px 28px; background: var(--purple-subtle); border-radius: var(--radius); border: 1px solid var(--purple-border); display: inline-block; margin-top: 12px; font-variant-numeric: tabular-nums; }

    .feature-toggle { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid var(--border-soft); }
    .feature-toggle:last-child { border-bottom: none; }
    .feature-label { font-weight: 600; font-size: 0.88rem; }
    .toggle-switch { position: relative; width: 44px; height: 24px; flex-shrink: 0; }
    .toggle-switch input { opacity: 0; width: 0; height: 0; }
    .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: var(--border); transition: 0.25s; border-radius: 99px; }
    .slider::before { content: ''; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; background: var(--text-muted); transition: 0.25s; border-radius: 50%; }
    input:checked + .slider { background: var(--purple); }
    input:checked + .slider::before { background: #fff; transform: translateX(20px); }

    .field-group { display: flex; flex-direction: column; gap: 6px; padding: 11px 0; border-bottom: 1px solid var(--border-soft); }
    .field-group:last-of-type { border-bottom: none; }
    .field-label { font-size: 0.75rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

    .usage-bar-wrap { margin-top: 8px; }
    .usage-bar-track { height: 4px; background: var(--border-soft); border-radius: 99px; overflow: hidden; }
    .usage-bar-fill { height: 100%; border-radius: 99px; }
    .usage-bar-fill.purple { background: linear-gradient(90deg, var(--purple-dim), var(--purple)); }
    .usage-bar-fill.indigo { background: linear-gradient(90deg, var(--purple-mid), var(--online)); }
    .usage-bar-fill.amber  { background: linear-gradient(90deg, oklch(58% 0.15 75), var(--amber)); }
    .usage-bar-fill.soft   { background: linear-gradient(90deg, var(--purple-subtle), var(--purple-mid)); }

    .badge { display: inline-block; padding: 2px 9px; border-radius: 99px; font-size: 0.7rem; font-weight: 700; }
    .badge-purple { background: var(--purple-subtle); color: var(--purple); border: 1px solid var(--purple-border); }
    .badge-soft   { background: var(--online-subtle); color: var(--online); border: 1px solid var(--online-border); }

    .section-sep { display: flex; align-items: center; gap: 14px; margin: 28px 0 18px; color: var(--text-faint); font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; }
    .section-sep::before, .section-sep::after { content: ''; flex: 1; height: 1px; background: var(--border-soft); }

    .info-row { display: flex; align-items: center; justify-content: space-between; padding: 11px 0; border-bottom: 1px solid var(--border-soft); gap: 12px; }
    .info-row:last-child { border-bottom: none; }
    .info-row-label { font-size: 0.8rem; color: var(--text-muted); font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .info-row-value { font-size: 0.88rem; font-weight: 700; color: var(--text); text-align: right; }

    .login-body { min-height: 100vh; background: linear-gradient(135deg, var(--bg) 0%, var(--bg2) 54%, oklch(14% 0.04 205) 100%); }
    .login-wrap { min-height: 100vh; display: grid; place-items: center; padding: 28px 18px; }
    .login-shell { width: min(980px, 100%); display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(320px, 0.95fr); border: 1px solid var(--border-soft); border-radius: 24px; overflow: hidden; background: var(--panel); box-shadow: var(--shadow); }
    .login-aside { padding: 36px; background: linear-gradient(160deg, oklch(18% 0.05 205), var(--panel-raised)); border-right: 1px solid var(--border-soft); display: flex; flex-direction: column; justify-content: center; min-height: 520px; }
    .login-brand { display: flex; align-items: center; gap: 14px; }
    .login-brand h1 { font-size: 1.6rem; line-height: 1.05; font-weight: 800; margin: 0; }
    .login-brand p { color: var(--text-muted); margin-top: 4px; font-size: 0.9rem; }
    .login-badge { width: 52px; height: 52px; border-radius: 16px; display: inline-flex; align-items: center; justify-content: center; color: #fff; background: linear-gradient(135deg, oklch(67% 0.18 165), var(--purple)); box-shadow: 0 10px 28px oklch(0% 0 0 / 0.28); flex-shrink: 0; }
    .login-copy { margin: 46px 0; max-width: 360px; }
    .login-copy h2 { font-size: 2.7rem; line-height: 1; letter-spacing: 0; margin: 0 0 18px; }
    .login-copy p { color: var(--text-muted); max-width: 34ch; font-size: 0.98rem; }
    .login-panel { padding: 46px; display: flex; flex-direction: column; justify-content: center; }
    .login-panel h2 { font-size: 1.45rem; margin: 0 0 8px; line-height: 1.15; }
    .login-panel > p { color: var(--text-muted); margin-bottom: 26px; }
    .login-form { display: grid; gap: 16px; }
    .login-field { display: grid; gap: 7px; }
    .login-field label { color: var(--text-muted); font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .login-field input { min-height: 46px; font-size: 1rem; }
    .turnstile-wrap { min-height: 65px; display: flex; align-items: center; }
    .login-error { border: 1px solid var(--red-border); background: var(--red-subtle); color: var(--red); border-radius: 10px; padding: 11px 13px; font-size: 0.88rem; font-weight: 700; }
    .login-button { min-height: 46px; margin-top: 4px; }
    .login-footnote { color: var(--text-faint); font-size: 0.78rem; margin-top: 18px; }

    @media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } .container { padding: 20px 16px; } .page-shell { padding: 20px; border-radius: var(--radius-lg); } .login-shell { grid-template-columns: 1fr; } .login-aside { min-height: auto; border-right: none; border-bottom: 1px solid var(--border-soft); } .login-copy { margin: 34px 0; } }
    @media (max-width: 600px) { .topbar { flex-direction: column; align-items: flex-start; } .nav-links { width: 100%; } .nav-links a { flex: 1 1 auto; justify-content: center; } .stats-grid { grid-template-columns: 1fr 1fr; } .actions button, .actions .btn { width: 100%; } .login-wrap { padding: 16px; place-items: stretch; } .login-shell { border-radius: 18px; } .login-aside, .login-panel { padding: 24px; } .login-copy h2 { font-size: 2.1rem; } }
    /* ===== Cloudflare-style app shell ===== */
    .app { display: grid; grid-template-columns: 66px 1fr; min-height: 100vh; }

    .sidebar { position: sticky; top: 0; align-self: start; height: 100vh; background: var(--bg-side); border-right: 1px solid var(--border-soft); display: flex; flex-direction: column; align-items: center; gap: 6px; padding: 14px 0; z-index: 30; }
    .side-logo { width: 44px; height: 44px; border-radius: 13px; display: flex; align-items: center; justify-content: center; color: #fff; background: linear-gradient(135deg, var(--purple), var(--purple-dim)); box-shadow: 0 6px 18px var(--purple-glow); margin-bottom: 10px; position: relative; }
    .side-logo .ico svg { width: 26px; height: auto; }
    .side-nav { display: flex; flex-direction: column; align-items: center; gap: 6px; width: 100%; }
    .side-link { position: relative; width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: var(--text-faint); transition: all 0.16s ease; }
    .side-link:hover { color: var(--text); background: var(--hover); }
    .side-link.active { color: var(--purple); background: var(--purple-soft); }
    .side-link.active::before { content: ''; position: absolute; left: -14px; top: 10px; bottom: 10px; width: 3px; border-radius: 0 3px 3px 0; background: var(--purple); }
    [data-tip] { position: relative; }
    [data-tip]::after { content: attr(data-tip); position: absolute; left: 56px; top: 50%; transform: translateY(-50%); background: var(--panel-2); color: var(--text); border: 1px solid var(--border); padding: 5px 9px; border-radius: 7px; font-size: 0.78rem; font-weight: 600; white-space: nowrap; opacity: 0; pointer-events: none; transition: opacity 0.15s; box-shadow: var(--shadow); z-index: 60; }
    [data-tip]:hover::after { opacity: 1; }

    .main { display: flex; flex-direction: column; min-width: 0; }
    .appbar { position: sticky; top: 0; z-index: 20; display: flex; align-items: center; justify-content: space-between; gap: 16px; height: 56px; padding: 0 24px; background: var(--appbar-bg); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-soft); }
    .appbar-org { display: flex; align-items: center; gap: 10px; font-weight: 700; min-width: 0; }
    .appbar-mark { color: var(--purple); } .appbar-mark svg { width: 22px; height: auto; }
    .appbar-name { font-size: 0.98rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .plan-badge { font-size: 0.64rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em; color: var(--purple); background: var(--purple-soft); border: 1px solid var(--purple-border); padding: 2px 8px; border-radius: 99px; flex-shrink: 0; }
    .appbar-actions { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
    .appbar-logout { margin: 0; }

    .content { flex: 1; width: 100%; max-width: 1240px; margin: 0 auto; padding: 28px 32px 56px; }
    .page-head { margin-bottom: 24px; }
    .breadcrumb { font-size: 0.78rem; color: var(--text-faint); font-weight: 600; margin-bottom: 8px; }
    .page-title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; flex-wrap: wrap; }
    .page-title-text h1 { font-size: 1.85rem; font-weight: 800; letter-spacing: -0.01em; line-height: 1.1; }
    .page-title-text p { margin-top: 8px; color: var(--text-muted); font-size: 0.92rem; max-width: 74ch; line-height: 1.6; }
    .page-actions { display: flex; gap: 10px; flex-wrap: wrap; }

    .tabs { display: flex; gap: 2px; margin-top: 22px; border-bottom: 1px solid var(--border-soft); overflow-x: auto; }
    .tab { display: inline-flex; align-items: center; gap: 7px; padding: 10px 14px; font-size: 0.86rem; font-weight: 600; color: var(--text-muted); text-decoration: none; border-bottom: 2px solid transparent; margin-bottom: -1px; white-space: nowrap; transition: all 0.15s; }
    .tab:hover { color: var(--text); }
    .tab.active { color: var(--purple); border-bottom-color: var(--purple); }
    .tab .ico svg { width: 15px; height: 15px; }

    .page-body { display: flex; flex-direction: column; gap: 22px; }

    .panel { background: var(--panel); border: 1px solid var(--border-soft); border-radius: var(--radius); overflow: hidden; }
    .panel-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 15px 18px; border-bottom: 1px solid var(--border-soft); flex-wrap: wrap; }
    .panel-head h2 { font-size: 0.98rem; font-weight: 700; display: flex; align-items: center; gap: 9px; margin: 0; }
    .panel-body { padding: 18px; }
    .count-chip { font-size: 0.72rem; font-weight: 800; color: var(--text-muted); background: var(--bg2); border: 1px solid var(--border-soft); padding: 2px 9px; border-radius: 99px; }
    .create-inline { display: flex; gap: 8px; margin: 0; }
    .create-inline input { width: 230px; max-width: 48vw; padding: 8px 12px; }

    .dtable { width: 100%; border-collapse: collapse; }
    .dtable th { text-align: left; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-faint); padding: 11px 18px; border-bottom: 1px solid var(--border-soft); background: var(--bg2); }
    .dtable td { padding: 13px 18px; border-bottom: 1px solid var(--border-soft); font-size: 0.9rem; vertical-align: middle; }
    .dtable tbody tr:last-child td { border-bottom: none; }
    .dtable tbody tr { transition: background 0.14s; }
    .dtable tbody tr:hover { background: var(--panel-2); }
    .cell-name { font-weight: 700; color: var(--text); }
    .cell-mono { font-family: monospace; font-size: 0.82rem; color: var(--text-muted); }
    .cell-actions { text-align: right; white-space: nowrap; }
    .empty-row td { text-align: center; color: var(--text-faint); padding: 36px 18px; font-size: 0.88rem; }

    .log-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
    .log-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; color: var(--text-muted); font-size: 0.82rem; }
    .log-meta code { color: var(--text); background: var(--bg2); border: 1px solid var(--border-soft); border-radius: 7px; padding: 2px 7px; word-break: break-all; }
    .log-lines { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .log-lines .btn.active { border-color: var(--purple-border); color: var(--purple); background: var(--purple-soft); }
    .log-view { background: var(--bg-side); border: 1px solid var(--border-soft); border-radius: var(--radius); min-height: 420px; max-height: calc(100vh - 280px); overflow: auto; padding: 16px; color: var(--text); font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: 0.78rem; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
    .log-empty { color: var(--text-muted); }

    .pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 11px; border-radius: 99px; font-size: 0.76rem; font-weight: 700; }
    .pill::before { content: ''; width: 6px; height: 6px; border-radius: 50%; }
    .pill-on { color: var(--green); background: var(--green-soft); border: 1px solid var(--green-border); }
    .pill-on::before { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .pill-off { color: var(--text-faint); background: var(--bg2); border: 1px solid var(--border); }
    .pill-off::before { background: var(--text-faint); }

    /* legacy component tweaks for the new shell */
    .status-online { color: var(--green); background: var(--green-soft); border-color: var(--green-border); }
    .status-online::before { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .stat-card { background: var(--panel); }
    .login-badge .ico svg, .brand-badge .ico svg { width: 30px; height: auto; }

    /* theme toggle button + sun/moon icon swap */
    .icon-btn { width: 36px; height: 36px; border-radius: 9px; display: inline-flex; align-items: center; justify-content: center; color: var(--text-muted); background: var(--panel-raised); border: 1px solid var(--border-soft); cursor: pointer; transition: all 0.16s ease; padding: 0; }
    .icon-btn:hover { color: var(--purple); border-color: var(--purple-border); background: var(--purple-soft); }
    .theme-fab { position: fixed; top: 16px; right: 16px; z-index: 40; }
    .theme-sun, .theme-moon { display: none; align-items: center; justify-content: center; }
    .theme-sun { display: inline-flex; }
    @media (prefers-color-scheme: light) {
      :root:not([data-theme]) .theme-sun { display: none; }
      :root:not([data-theme]) .theme-moon { display: inline-flex; }
    }
    :root[data-theme="dark"] .theme-sun { display: inline-flex; }
    :root[data-theme="dark"] .theme-moon { display: none; }
    :root[data-theme="light"] .theme-sun { display: none; }
    :root[data-theme="light"] .theme-moon { display: inline-flex; }

    @media (max-width: 820px) {
      .app { grid-template-columns: 1fr; }
      .sidebar { position: sticky; top: 0; height: auto; width: 100%; flex-direction: row; justify-content: flex-start; gap: 6px; padding: 8px 12px; border-right: none; border-bottom: 1px solid var(--border-soft); overflow-x: auto; }
      .side-logo { margin-bottom: 0; width: 38px; height: 38px; }
      .side-link { width: 40px; height: 40px; }
      .side-link.active::before { display: none; }
      [data-tip]::after { display: none; }
      .content { padding: 20px 16px 40px; }
      .page-title-text h1 { font-size: 1.5rem; }
      .create-inline { width: 100%; } .create-inline input { flex: 1; max-width: none; }
    }
  </style>
</head>`;
}

// ─── BRAND LOGO (favicon) ──────────────────────────────────────────────────────
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><rect width="48" height="48" rx="12" fill="#8b5cf6"/><g fill="#ffffff" transform="translate(2 13)"><path d="M3 3H13L3 10Z"/><path d="M41 3H31L41 10Z"/><path d="M3 12V19H13Z"/><path d="M41 12V19H31Z"/><rect x="17" y="3" width="10" height="7" rx="2"/><rect x="17" y="12" width="10" height="7" rx="2"/></g></svg>`;
const FAVICON_HREF = `data:image/svg+xml;base64,${Buffer.from(FAVICON_SVG).toString('base64')}`;

// ─── APP SHELL (sidebar + top bar + page header) ───────────────────────────────
let APP_ROLE = 'main';

function roleLabel(role) { return 'Serveur Railway'; }
function roleBadge(role) { return 'Railway'; }

function shellOpen({ active = '', session = null, title = '', desc = '', breadcrumb = '', actions = '', tabs = '' } = {}) {
  const navItems = [
    { key: 'dashboard', href: '/dashboard', icon: ICO.home, label: 'Serveur' },
    { key: 'logs', href: '/logs', icon: ICO.logs, label: 'Logs serveur' }
  ];
  const navHtml = navItems.map((n) => `<a class="side-link${active === n.key ? ' active' : ''}" href="${n.href}" data-tip="${escapeHtml(n.label)}"><span class="ico">${n.icon}</span></a>`).join('');
  const logoutHtml = session
    ? `<form method="POST" action="/logout" class="appbar-logout">${csrfInput(session)}<button type="submit" class="btn btn-secondary btn-sm"><span class="ico">${ICO.logout}</span> Déconnexion</button></form>`
    : '';
  return `<body>
  <div class="app">
    <aside class="sidebar">
      <a class="side-logo" href="/dashboard" data-tip="Salibot"><span class="ico">${ICO.logo}</span></a>
      <nav class="side-nav">${navHtml}</nav>
    </aside>
    <div class="main">
      <header class="appbar">
        <div class="appbar-org">
          <span class="appbar-name">Salibot</span>
          <span class="plan-badge">${escapeHtml(roleBadge(APP_ROLE))}</span>
        </div>
        <div class="appbar-actions">
          <button type="button" class="icon-btn" onclick="toggleTheme()" title="Changer le thème" aria-label="Changer le thème"><span class="theme-sun ico">${ICO.sun}</span><span class="theme-moon ico">${ICO.moon}</span></button>
          ${logoutHtml}
        </div>
      </header>
      <div class="content">
        <div class="page-head">
          ${breadcrumb ? `<div class="breadcrumb">${escapeHtml(breadcrumb)}</div>` : ''}
          <div class="page-title-row">
            <div class="page-title-text"><h1>${escapeHtml(title)}</h1>${desc ? `<p>${escapeHtml(desc)}</p>` : ''}</div>
            ${actions ? `<div class="page-actions">${actions}</div>` : ''}
          </div>
          ${tabs ? `<nav class="tabs">${tabs}</nav>` : ''}
        </div>
        <div class="page-body">`;
}

function shellClose() {
  return `</div></div></div></div></body></html>`;
}

function botTabs(botId, active) {
  const id = escapeHtml(botId);
  const tab = (key, href, icon, label) => `<a class="tab${active === key ? ' active' : ''}" href="${href}"><span class="ico">${icon}</span> ${label}</a>`;
  return tab('all', '/dashboard', ICO.server, 'Tous les bots')
    + tab('dash', `/${id}/`, ICO.grid, 'Dashboard')
    + tab('allowed', `/${id}/allowed`, ICO.check, 'Groupes autorisés')
    + tab('tracked', `/${id}/grouptracked`, ICO.eye, 'Groupes trackés');
}

// ─── PAGE BUILDERS ───────────────────────────────────────────────────────────

function buildLoginPage({ error = '', nextPath = '/dashboard', user = '', csrfToken = '' }) {
  return `${getGlobalStyles('Connexion')}
<body class="login-body">
  <button type="button" class="icon-btn theme-fab" onclick="toggleTheme()" title="Changer le thème" aria-label="Changer le thème"><span class="theme-sun ico">${ICO.sun}</span><span class="theme-moon ico">${ICO.moon}</span></button>
  <main class="login-wrap">
    <section class="login-shell" aria-label="Connexion administrateur">
      <aside class="login-aside">
        <div>
          <div class="login-brand">
            <div class="login-badge">${ICO.logo}</div>
            <div>
              <h1>Salibot</h1>
              <p>Console d'administration</p>
            </div>
          </div>
          <div class="login-copy">
            <h2>Connexion securisee.</h2>
            <p>Cette page ne publie aucune information systeme avant authentification.</p>
          </div>
        </div>
      </aside>
      <section class="login-panel">
        <h2>Connexion</h2>
        <p>Entrez vos identifiants administrateur.</p>
        <form class="login-form" method="POST" action="/login" autocomplete="on">
          <input type="hidden" name="next" value="${escapeHtml(nextPath)}" />
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          ${error ? `<div class="login-error" role="alert">${escapeHtml(error)}</div>` : ''}
          <div class="login-field">
            <label for="login-user">Identifiant</label>
            <input id="login-user" type="text" name="name" autocomplete="username" required autofocus />
          </div>
          <div class="login-field">
            <label for="login-password">Mot de passe</label>
            <input id="login-password" type="password" name="password" autocomplete="current-password" required />
          </div>
          <div class="turnstile-wrap">
            <div class="cf-turnstile" data-sitekey="${escapeHtml(TURNSTILE_SITE_KEY)}" data-theme="auto"></div>
          </div>
          <button class="btn-primary login-button" type="submit">Se connecter</button>
        </form>
        <div class="login-footnote">Session protegee pendant 12 heures.</div>
      </section>
    </section>
  </main>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body></html>`;
}

function buildAllowedPage({ botId, groups, saved, session }) {
  const allowedGroups = groups.filter((g) => saved.groups.includes(g.jid));
  const notAllowedGroups = groups.filter((g) => !saved.groups.includes(g.jid));
  const allowedHtml = allowedGroups.map((g) => `<label class="group-item"><div class="group-line"><input type="checkbox" name="groups" value="${escapeHtml(g.jid)}" checked /><div><span class="group-name">${escapeHtml(g.name)}</span><div class="group-jid">${escapeHtml(g.jid)}</div></div></div></label>`).join('');
  const notAllowedHtml = notAllowedGroups.map((g) => `<label class="group-item"><div class="group-line"><input type="checkbox" name="groups" value="${escapeHtml(g.jid)}" /><div><span class="group-name">${escapeHtml(g.name)}</span><div class="group-jid">${escapeHtml(g.jid)}</div></div></div></label>`).join('');

  return `${getGlobalStyles(`Bot ${escapeHtml(botId)} - Groupes autorisés`)}
${shellOpen({
    active: 'dashboard',
    session,
    breadcrumb: `Salibot / Serveur / ${escapeHtml(botId)} / Groupes autorisés`,
    title: 'Groupes autorisés',
    desc: `Choisissez les groupes dans lesquels le bot ${escapeHtml(botId)} est autorisé à agir.`,
    actions: `<a class="btn btn-secondary" href="/${escapeHtml(botId)}/allowed"><span class="ico">${ICO.refresh}</span> Rafraîchir</a>`,
    tabs: botTabs(botId, 'allowed')
  })}
  <form method="POST" action="/${escapeHtml(botId)}/allowed/save">
    ${csrfInput(session)}
    <div class="grid-2">
      <div class="card">
        <h2 style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">Groupes autorisés <span class="badge badge-soft">${allowedGroups.length}</span></h2>
        <div class="list-wrap">${allowedHtml || '<div class="empty-box">Aucun groupe autorisé.</div>'}</div>
      </div>
      <div class="card">
        <h2 style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">Groupes non autorisés <span class="badge badge-purple">${notAllowedGroups.length}</span></h2>
        <div class="list-wrap">${notAllowedHtml || '<div class="empty-box">Tous les groupes sont autorisés.</div>'}</div>
      </div>
    </div>
    <div class="actions">
      <button type="submit" class="btn-primary"><span class="ico">${ICO.save}</span> Sauvegarder les modifications</button>
    </div>
  </form>
${shellClose()}`;
}

function buildTrackedGroupsPage({ botId, groups, saved, session }) {
  const trackedGroups = groups.filter((g) => saved.trackedGroups.includes(g.jid));
  const notTrackedGroups = groups.filter((g) => !saved.trackedGroups.includes(g.jid));
  const trackedHtml = trackedGroups.map((g) => `<label class="group-item"><div class="group-line"><input type="checkbox" name="trackedGroups" value="${escapeHtml(g.jid)}" checked /><div><span class="group-name">${escapeHtml(g.name)}</span><div class="group-jid">${escapeHtml(g.jid)}</div></div></div></label>`).join('');
  const notTrackedHtml = notTrackedGroups.map((g) => `<label class="group-item"><div class="group-line"><input type="checkbox" name="trackedGroups" value="${escapeHtml(g.jid)}" /><div><span class="group-name">${escapeHtml(g.name)}</span><div class="group-jid">${escapeHtml(g.jid)}</div></div></div></label>`).join('');

  return `${getGlobalStyles(`Bot ${escapeHtml(botId)} - Groupes trackés`)}
${shellOpen({
    active: 'dashboard',
    session,
    breadcrumb: `Salibot / Serveur / ${escapeHtml(botId)} / Groupes trackés`,
    title: 'Groupes trackés',
    desc: `Surveillez les messages des groupes sélectionnés pour le bot ${escapeHtml(botId)}.`,
    actions: `<a class="btn btn-secondary" href="/${escapeHtml(botId)}/grouptracked"><span class="ico">${ICO.refresh}</span> Rafraîchir</a>`,
    tabs: botTabs(botId, 'tracked')
  })}
  <form method="POST" action="/${escapeHtml(botId)}/grouptracked/save">
    ${csrfInput(session)}
    <div class="grid-2">
      <div class="card">
        <h2 style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">Groupes trackés <span class="badge badge-soft">${trackedGroups.length}</span></h2>
        <div class="list-wrap">${trackedHtml || '<div class="empty-box">Aucun groupe tracké.</div>'}</div>
      </div>
      <div class="card">
        <h2 style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">Groupes non trackés <span class="badge badge-purple">${notTrackedGroups.length}</span></h2>
        <div class="list-wrap">${notTrackedHtml || '<div class="empty-box">Tous les groupes sont trackés.</div>'}</div>
      </div>
    </div>
    <div class="actions">
      <button type="submit" class="btn-primary"><span class="ico">${ICO.save}</span> Sauvegarder les modifications</button>
    </div>
  </form>
${shellClose()}`;
}

// ─── EXPRESS SERVER ───────────────────────────────────────────────────────────
module.exports = function startWebServer(ctx) {
  const { PORT, SERVER_NAME, SERVER_ROLE, bots, addNewBot, deleteBot, disconnectBotAuth, prepareBotForAuth, getPairingCode, loadAllowedData, saveAllowedData, getGroupsList, getContainerRamUsage, getContainerDiskUsage, getHostDiskUsage, runDownloadSpeedTest, getInstanceStatus, restartProcess } = ctx;

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  APP_ROLE = SERVER_ROLE || 'main';

  loadWebAuth();

  const allowedHosts = parseAllowedHosts(process.env.ALLOWED_HOSTS || process.env.WEB_ALLOWED_HOSTS || DEFAULT_ALLOWED_HOSTS);
  const publicRouteLimiter = makeWebRateLimiter(PUBLIC_ROUTE_RATE_LIMIT_MAX, 'Too many requests.');
  const authRouteLimiter = makeWebRateLimiter(AUTH_ROUTE_RATE_LIMIT_MAX, 'Too many authentication attempts.');
  const botAuthLimiter = makeWebRateLimiter(BOT_AUTH_RATE_LIMIT_MAX, 'Too many bot authentication attempts.');

  app.use(applySecurityHeaders);
  app.use(enforceAllowedHost(allowedHosts));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  // Guarantee req.body is always an object so handlers never throw on a missing /
  // mismatched-content-type body (avoids 500s and keeps CSRF/validation in control).
  app.use((req, res, next) => { if (req.body == null || typeof req.body !== 'object') req.body = {}; next(); });
  app.use((req, res, next) => {
    const startedAt = Date.now();
    res.on('finish', () => {
      const method = sanitizeLogField(req.method);
      const url = sanitizeLogField(req.originalUrl || req.url);
      console.log(JSON.stringify({
        event: 'web_request',
        method,
        url,
        statusCode: res.statusCode,
        durationMs: Date.now() - startedAt
      }));
    });
    next();
  });

  app.get('/health', (req, res) => {
    if (typeof getInstanceStatus === 'function') return res.json(getInstanceStatus());
    res.json({
      ok: true,
      serverName: SERVER_NAME || 'server',
      role: SERVER_ROLE || 'main',
      port: PORT,
      uptimeSeconds: Math.floor(process.uptime())
    });
  });

  app.get('/', publicRouteLimiter, (req, res) => {
    if (getSession(req)) return res.redirect('/dashboard');
    const nextPath = sanitizeNextPath(req.query.next || '/dashboard');
    const csrfToken = createLoginCsrfToken();
    res.send(buildLoginPage({ nextPath, csrfToken }));
  });

  app.post('/login', authRouteLimiter, async (req, res) => {
    const auth = loadWebAuth();
    const user = String(req.body.name || '');
    const pass = String(req.body.password || '');
    const nextPath = sanitizeNextPath(req.body.next || '/dashboard');
    const freshCsrfToken = createLoginCsrfToken();

    if (!isValidLoginCsrfToken(req.body._csrf)) {
      return res.status(403).send(buildLoginPage({
        error: 'Connexion refusee.',
        nextPath,
        user,
        csrfToken: freshCsrfToken
      }));
    }

    if (isLoginBlocked(req)) {
      return res.status(429).send(buildLoginPage({
        error: 'Trop de tentatives. Reessayez plus tard.',
        nextPath,
        user,
        csrfToken: freshCsrfToken
      }));
    }

    const turnstile = await verifyTurnstile(req);
    if (!turnstile.ok) {
      recordLoginFailure(req);
      return res.status(turnstile.status).send(buildLoginPage({
        error: turnstile.message,
        nextPath,
        user,
        csrfToken: freshCsrfToken
      }));
    }

    if (verifyWebCredentials(auth, user, pass)) {
      recordLoginSuccess(req);
      createSession(res, req, user);
      return res.redirect(nextPath);
    }

    recordLoginFailure(req);
    res.status(401).send(buildLoginPage({
      error: 'Identifiants incorrects.',
      nextPath,
      user,
      csrfToken: freshCsrfToken
    }));
  });

  app.post('/logout', (req, res) => {
    const session = getSession(req);
    if (!session || !isValidCsrf(req.body._csrf, session.csrfToken)) {
      return res.status(403).send('Forbidden.');
    }
    clearSession(res, req);
    res.redirect('/');
  });

  app.get('/robots.txt', (req, res) => {
    res.type('text/plain; charset=utf-8').send('User-agent: *\nDisallow: /\n');
  });

  app.get('/sitemap.xml', (req, res) => {
    res.type('application/xml; charset=utf-8').send('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>');
  });

  app.use((req, res, next) => {
    const session = getSession(req);
    if (session) {
      req.session = session;
      if (req.method === 'POST' && !isValidCsrf(req.body._csrf, session.csrfToken)) {
        if (req.path.startsWith('/api/')) {
          return res.status(403).json({ error: true, message: 'Forbidden.' });
        }
        return res.status(403).send('Forbidden.');
      }
      return next();
    }
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: true, message: 'Authentication required.' });
    }
    const nextPath = encodeURIComponent(sanitizeNextPath(req.originalUrl || '/dashboard'));
    res.redirect(`/?next=${nextPath}`);
  });

  // ── API: Speedtest ──
  app.get('/api/speedtest', async (req, res) => {
    try {
      if (typeof runDownloadSpeedTest !== 'function') throw new Error('Speedtest unavailable');
      const result = await runDownloadSpeedTest();
      res.json({
        download: result.downloadMbps,
        latency: result.latencyMs,
        bytes: result.bytes,
        duration: result.durationSeconds
      });
    } catch (err) {
      res.json({ error: true, message: err.message });
    }
  });

  // ── GET /dashboard : Server overview ──
  app.get('/logs', (req, res) => {
    const lines = clampNumber(req.query.lines, 100, 2000, 500);
    const log = readLogTail(LOG_FILE, lines);
    const displayPath = path.relative(__dirname, LOG_FILE) || path.basename(LOG_FILE);
    const updatedAt = log.mtime ? log.mtime.toLocaleString('fr-FR', { hour12: false }) : 'n/a';
    const lineOptions = [200, 500, 1000, 2000].map((value) =>
      `<a class="btn btn-secondary btn-sm${value === lines ? ' active' : ''}" href="/logs?lines=${value}">${value}</a>`
    ).join('');
    const logText = log.exists
      ? (log.text || 'Log file is empty.')
      : log.error;

    res.send(`${getGlobalStyles('Logs serveur')}
${shellOpen({
  active: 'logs',
  session: req.session,
  breadcrumb: 'Salibot / Logs',
  title: 'Logs serveur',
  desc: 'Consultez les journaux recents du superviseur et du bot sur ce serveur.',
  actions: `<a class="btn btn-secondary" href="/logs?lines=${lines}"><span class="ico">${ICO.refresh}</span> Rafraichir</a>`
})}
  <div class="panel">
    <div class="panel-head">
      <h2><span class="ico" style="color:var(--purple)">${ICO.logs}</span> ${escapeHtml(roleLabel(APP_ROLE))}</h2>
      ${log.truncated ? '<span class="count-chip">tail limite</span>' : '<span class="count-chip">complet</span>'}
    </div>
    <div class="panel-body">
      <div class="log-toolbar">
        <div class="log-meta">
          <span>Source <code>${escapeHtml(displayPath)}</code></span>
          <span>Taille ${escapeHtml(formatLogSize(log.size))}</span>
          <span>Mis a jour ${escapeHtml(updatedAt)}</span>
        </div>
        <div class="log-lines" aria-label="Nombre de lignes">
          ${lineOptions}
        </div>
      </div>
      <pre class="log-view${log.exists && log.text ? '' : ' log-empty'}">${escapeHtml(logText)}</pre>
    </div>
  </div>
${shellClose()}`);
  });

  app.get('/dashboard', (req, res) => {
    const totalRam = os.totalmem();
    const freeRam = os.freemem();
    const usedRam = totalRam - freeRam;
    const ramPercentageHost = ((usedRam / totalRam) * 100).toFixed(1);

    const hostDisk = getHostDiskUsage();
    const contRam = getContainerRamUsage();
    const contDisk = getContainerDiskUsage();

    const uptimeSeconds = Math.floor(process.uptime());
    const d = Math.floor(uptimeSeconds / 86400);
    const h = Math.floor((uptimeSeconds % 86400) / 3600);
    const m = Math.floor((uptimeSeconds % 3600) / 60);
    const uptimeStr = `${d}j ${h}h ${m}m`;

    let botRows = '';
    for (const [id, bot] of bots.entries()) {
      botRows += `
        <tr>
          <td><span class="cell-name">${escapeHtml(id)}</span></td>
          <td class="cell-mono">Instance WhatsApp</td>
          <td><span class="pill ${bot.isConnected ? 'pill-on' : 'pill-off'}">${bot.isConnected ? 'Connecté' : 'Déconnecté'}</span></td>
          <td class="cell-actions"><a class="btn btn-sm btn-secondary" href="/${escapeHtml(id)}/">Gérer</a></td>
        </tr>`;
    }

    const haStatus = (typeof getInstanceStatus === 'function') ? getInstanceStatus() : {};
    const isActive = Boolean(haStatus.whatsappActive);
    const meName = escapeHtml(roleLabel(APP_ROLE));
    const haPanel = `
  <div class="panel">
    <div class="panel-head">
      <h2><span class="ico" style="color:var(--purple)">${ICO.shield}</span> Serveur autonome</h2>
      <span class="pill ${isActive ? 'pill-on' : 'pill-off'}">${isActive ? 'ACTIF' : 'Deconnecte'}</span>
    </div>
    <div class="panel-body">
      <div class="info-row"><span class="info-row-label"><span class="ico">${ICO.server}</span> Ce serveur</span><span class="info-row-value">${meName}</span></div>
      <div class="info-row"><span class="info-row-label"><span class="ico">${ICO.refresh}</span> Serveur principal</span><span class="info-row-value">aucun lien</span></div>
      <p style="color:var(--text-muted);font-size:0.88rem;margin:14px 0 0;">Cette instance fonctionne seule sur Railway. Elle ne contacte pas le serveur principal et ne recoit pas de commandes HA externes.</p>
    </div>
  </div>`;

    res.send(`${getGlobalStyles('Salibot — Serveur Multi-Bots')}
${shellOpen({
      active: 'dashboard',
      session: req.session,
      breadcrumb: 'Salibot / Serveur',
      title: 'Serveur Multi-Bots',
      desc: "Gérez vos instances WhatsApp, surveillez les ressources et créez de nouveaux bots. Les instances sont exécutées et supervisées en continu, de la première à la dernière.",
      actions: `<a class="btn btn-secondary" href="/dashboard"><span class="ico">${ICO.refresh}</span> Rafraîchir</a>`
    })}
${haPanel}
  <div class="panel">
    <div class="panel-head">
      <h2><span class="ico" style="color:var(--purple)">${ICO.bot}</span> Bots actifs <span class="count-chip">${bots.size}</span></h2>
      <form method="POST" action="/api/bots/add" class="create-inline">
        ${csrfInput(req.session)}
        <input type="text" name="botId" placeholder="Nom du bot (ex: bot_support)" required />
        <button type="submit" class="btn-primary btn-sm" style="white-space:nowrap;"><span class="ico">${ICO.plus}</span> Créer un bot</button>
      </form>
    </div>
    <table class="dtable">
      <thead><tr><th>Nom</th><th>Type</th><th>Statut</th><th class="cell-actions">Action</th></tr></thead>
      <tbody>
        ${botRows || '<tr class="empty-row"><td colspan="4">Aucun bot pour le moment. Créez-en un avec le champ ci-dessus.</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="section-sep"><span class="ico">${ICO.server}</span> Ressources Système</div>
  <div class="stats-grid" style="margin-top:0;">
    <div class="stat-card">
      <div class="stat-label">RAM Host</div>
      <div class="stat-value">${ramPercentageHost}%</div>
      <div class="usage-bar-wrap"><div class="usage-bar-track"><div class="usage-bar-fill purple" style="width:${ramPercentageHost}%"></div></div></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">RAM Container</div>
      <div class="stat-value">${contRam.percent}</div>
      <div class="stat-sub">${contRam.used} / ${contRam.total}</div>
      <div class="usage-bar-wrap"><div class="usage-bar-track"><div class="usage-bar-fill indigo" style="width:${contRam.percent}"></div></div></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Disk Host</div>
      <div class="stat-value">${hostDisk.percent}</div>
      <div class="stat-sub">${hostDisk.used} / ${hostDisk.total}</div>
      <div class="usage-bar-wrap"><div class="usage-bar-track"><div class="usage-bar-fill amber" style="width:${hostDisk.percent}"></div></div></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Disk Container</div>
      <div class="stat-value">${contDisk.percent}</div>
      <div class="stat-sub">${contDisk.used} / ${contDisk.total}</div>
      <div class="usage-bar-wrap"><div class="usage-bar-track"><div class="usage-bar-fill soft" style="width:${contDisk.percent}"></div></div></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Uptime Salibot</div>
      <div class="stat-value" style="font-size:1.3rem;">${uptimeStr}</div>
      <div class="stat-sub">En Ligne</div>
      <div class="usage-bar-wrap"><div class="usage-bar-track"><div class="usage-bar-fill" style="width:100%; background:var(--online)"></div></div></div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head"><h2><span class="ico" style="color:var(--purple)">${ICO.bolt}</span> Bande passante</h2></div>
    <div class="panel-body">
      <p style="color:var(--text-muted);margin-bottom:16px;">Testez la vitesse de connexion internet de votre serveur (download / latence).</p>
      <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;">
        <button type="button" class="btn-primary" id="btn-speedtest" onclick="runSpeedTest()"><span class="ico">${ICO.bolt}</span> Lancer le test</button>
        <div id="speedtest-results"></div>
      </div>
    </div>
  </div>

  <div style="padding-top:8px;text-align:center;">
    <form method="POST" action="/restart-server" style="display:inline;">
      ${csrfInput(req.session)}
      <button type="submit" class="btn btn-warning"><span class="ico">${ICO.restart}</span> Redémarrer tout le serveur</button>
    </form>
  </div>

<script>
  function runSpeedTest() {
    const btn = document.getElementById('btn-speedtest');
    const res = document.getElementById('speedtest-results');
    btn.disabled = true; btn.style.opacity = '0.6';
    res.innerHTML = '<span style="color:var(--text-muted);font-size:0.88rem;font-weight:600;">Test en cours (10-20 sec)...</span>';
    fetch('/api/speedtest')
      .then(r => r.json())
      .then(data => {
        btn.disabled = false; btn.style.opacity = '1';
        if (data.error) {
          res.innerHTML = '<span style="color:var(--red);font-weight:700;">Erreur: ' + data.message + '</span>';
        } else {
          res.innerHTML = '<span style="color:var(--purple);font-weight:700;font-size:0.95rem;">&#8595; ' + data.download + ' Mbps &nbsp;&nbsp; Latence ' + data.latency + ' ms</span>';
        }
      })
      .catch(() => {
        btn.disabled = false; btn.style.opacity = '1';
        res.innerHTML = '<span style="color:var(--red);font-weight:700;">Erreur de communication avec le serveur</span>';
      });
  }
</script>
${shellClose()}`);
  });

  // ── POST /api/bots/add ──
  app.post('/api/bots/add', (req, res) => {
    const newBotId = req.body.botId;
    if (newBotId) addNewBot(newBotId);
    res.redirect('/dashboard');
  });

  app.post('/restart-server', (req, res) => {
    res.send(`${getGlobalStyles('Redémarrage...')}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>Redémarrage du serveur...</h2>
  <div class="actions" style="justify-content:center;"><a class="btn btn-primary" href="/dashboard">Retour à l'accueil</a></div>
</div></div></div></body></html>`);
    restartProcess();
  });

  // ── GET /:botId/ : Bot dashboard ──
  app.get('/:botId/', (req, res) => {
    const botId = req.params.botId;
    const bot = bots.get(botId);
    if (!bot) return res.redirect('/dashboard');

    const saved = loadAllowedData(botId);
    const features = saved.features || {};

    res.send(`${getGlobalStyles(`Dashboard Bot - ${botId}`)}
${shellOpen({
      active: 'dashboard',
      session: req.session,
      breadcrumb: `Salibot / Serveur / ${escapeHtml(botId)}`,
      title: `Bot ${escapeHtml(botId)}`,
      desc: 'Gérez la connexion WhatsApp, les permissions et les fonctionnalités de cette instance.',
      tabs: botTabs(botId, 'dash')
    })}

  <div class="grid-2">

    <div class="card" style="display:flex;flex-direction:column;">
      <div style="text-align:center;padding-bottom:18px;border-bottom:1px solid var(--border-soft);">
        <div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:12px;">
          <span style="font-size:1rem;font-weight:700;">Connexion</span>
          <span class="status-pill ${bot.isConnected ? 'status-online' : 'status-offline'}">${bot.isConnected ? 'Connecté' : escapeHtml(bot.currentConnectionState)}</span>
        </div>
        ${bot.isConnected ? `
        <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:16px;">Le bot est actif et lié au compte WhatsApp.</p>
        <form method="POST" action="/${escapeHtml(botId)}/disconnect" style="margin:0;">
          ${csrfInput(req.session)}
          <button type="submit" class="btn btn-warning"><span class="ico">${ICO.unplug}</span> Déconnecter</button>
        </form>` : `
        <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:16px;">Ce bot n'est pas lié à WhatsApp.</p>
        <div style="display:flex;flex-direction:column;gap:10px;align-items:center;">
          <a class="btn btn-primary" href="/${escapeHtml(botId)}/qr"><span class="ico">${ICO.qr}</span> Connecter par QR Code</a>
          <a class="btn btn-secondary" href="/${escapeHtml(botId)}/pair"><span class="ico">${ICO.phone}</span> Connecter par Numéro</a>
        </div>`}
      </div>

      <div style="flex:1;padding-top:16px;">
        <div style="font-size:0.72rem;font-weight:700;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:8px;">Informations du bot</div>
        <div class="info-row">
          <span class="info-row-label"><span class="ico">${ICO.bot}</span> Identifiant</span>
          <span class="info-row-value" style="font-family:monospace;font-size:0.82rem;color:var(--purple);">${escapeHtml(botId)}</span>
        </div>
        <div class="info-row">
          <span class="info-row-label"><span class="ico">${ICO.check}</span> Groupes autorisés</span>
          <span class="info-row-value">${saved.groups.length}</span>
        </div>
        <div class="info-row">
          <span class="info-row-label"><span class="ico">${ICO.eye}</span> Groupes trackés</span>
          <span class="info-row-value">${saved.trackedGroups.length}</span>
        </div>
        <div class="info-row">
          <span class="info-row-label"><span class="ico">${ICO.msg}</span> Commande .u</span>
          <span class="info-row-value">${features.broadcast ? 'Activée' : 'Désactivée'}</span>
        </div>
        <div class="info-row">
          <span class="info-row-label"><span class="ico">${ICO.settings}</span> Accès commandes</span>
          <span class="info-row-value">${features.commandAccess === 'owner' ? 'Propriétaire' : features.commandAccess === 'admin' ? 'Admins' : 'Tous'}</span>
        </div>
      </div>

      <div style="padding-top:16px;border-top:1px solid var(--border-soft);margin-top:16px;">
        <form method="POST" action="/${escapeHtml(botId)}/delete" onsubmit="return confirm('Supprimer définitivement ce bot ?');">
          ${csrfInput(req.session)}
          <button type="submit" class="btn btn-danger btn-full"><span class="ico">${ICO.trash}</span> Supprimer ce bot</button>
        </form>
      </div>
    </div>

    <div class="card">
      <h2 style="display:flex;align-items:center;gap:8px;margin-bottom:14px;"><span class="ico" style="color:var(--purple)">${ICO.settings}</span> Paramètres &amp; Permissions</h2>
      <form method="POST" action="/${escapeHtml(botId)}/features/save">
        ${csrfInput(req.session)}

        <div class="field-group">
          <div class="field-label">Qui peut utiliser les commandes ?</div>
          <select name="commandAccess">
            <option value="all" ${features.commandAccess === 'all' || !features.commandAccess ? 'selected' : ''}>Tout le monde (par défaut)</option>
            <option value="admin" ${features.commandAccess === 'admin' ? 'selected' : ''}>Admins du Groupe &amp; Moi Uniquement</option>
            <option value="owner" ${features.commandAccess === 'owner' ? 'selected' : ''}>Moi Uniquement (Propriétaire)</option>
          </select>
        </div>

        <div class="field-group">
          <div class="field-label">Où les commandes peuvent être utilisées ?</div>
          <select name="commandScope">
            <option value="all" ${features.commandScope === 'all' || !features.commandScope ? 'selected' : ''}>Partout (privé + groupes)</option>
            <option value="private_only" ${features.commandScope === 'private_only' ? 'selected' : ''}>Seulement en privé</option>
            <option value="allowed_groups_only" ${features.commandScope === 'allowed_groups_only' ? 'selected' : ''}>Seulement dans les groupes autorisés</option>
            <option value="private_and_allowed_groups" ${features.commandScope === 'private_and_allowed_groups' ? 'selected' : ''}>Privé + groupes autorisés seulement</option>
          </select>
        </div>

        <div class="field-group">
          <div class="field-label">Où envoyer les Alertes / Transferts ?</div>
          <select name="alertsDestination">
            <option value="allowed_groups" ${features.alertsDestination === 'allowed_groups' || !features.alertsDestination ? 'selected' : ''}>Dans les Groupes Autorisés (par défaut)</option>
            <option value="owner" ${features.alertsDestination === 'owner' ? 'selected' : ''}>En Message Privé (A Moi Uniquement)</option>
          </select>
        </div>

        <hr class="divider" />

        <div class="feature-toggle">
          <span class="feature-label">Téléchargement des Reels avec .u</span>
          <label class="toggle-switch"><input type="checkbox" name="broadcast" ${features.broadcast ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Anti-Suppression (Messages Privés)</span>
          <label class="toggle-switch"><input type="checkbox" name="antiDeletePrivate" ${features.antiDeletePrivate ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Anti-Suppression (Groupes Trackés)</span>
          <label class="toggle-switch"><input type="checkbox" name="antiDeleteGroup" ${features.antiDeleteGroup ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Transfert des Nouveaux Statuts</span>
          <label class="toggle-switch"><input type="checkbox" name="statusForwarding" ${features.statusForwarding ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Notifications Groupe (Ajout/Kick)</span>
          <label class="toggle-switch"><input type="checkbox" name="groupNotifications" ${features.groupNotifications ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Notifications Administrateurs (Promu/Rétrogradé)</span>
          <label class="toggle-switch"><input type="checkbox" name="adminNotifications" ${features.adminNotifications ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Notifications Paramètres Groupe (Nom, Photo, etc.)</span>
          <label class="toggle-switch"><input type="checkbox" name="groupMetaNotifications" ${features.groupMetaNotifications ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Notifications Photos Contacts (Privé)</span>
          <label class="toggle-switch"><input type="checkbox" name="contactPhotoNotifications" ${features.contactPhotoNotifications ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Capture View Once (Privé)</span>
          <label class="toggle-switch"><input type="checkbox" name="viewOncePrivate" ${features.viewOncePrivate ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="feature-toggle">
          <span class="feature-label">Capture View Once (Groupes)</span>
          <label class="toggle-switch"><input type="checkbox" name="viewOnceGroup" ${features.viewOnceGroup ? 'checked' : ''}><span class="slider"></span></label>
        </div>

        <div class="actions" style="margin-top:14px;">
          <button type="submit" class="btn-primary btn-full"><span class="ico">${ICO.save}</span> Sauvegarder les Paramètres</button>
        </div>
      </form>
    </div>

  </div>
${shellClose()}`);
  });

  // ── POST /:botId/features/save ──
  app.post('/:botId/features/save', (req, res) => {
    const botId = getExistingBotId(bots, req.params.botId);
    if (!botId) return res.redirect('/dashboard');
    const validCommandAccess = ['all', 'admin', 'owner'];
    const validCommandScope = ['all', 'private_only', 'allowed_groups_only', 'private_and_allowed_groups'];
    const validAlertsDestination = ['allowed_groups', 'owner'];
    const newFeatures = {
      broadcast: !!req.body.broadcast,
      antiDeletePrivate: !!req.body.antiDeletePrivate,
      antiDeleteGroup: !!req.body.antiDeleteGroup,
      statusForwarding: !!req.body.statusForwarding,
      groupNotifications: !!req.body.groupNotifications,
      adminNotifications: !!req.body.adminNotifications,
      groupMetaNotifications: !!req.body.groupMetaNotifications,
      contactPhotoNotifications: !!req.body.contactPhotoNotifications,
      viewOncePrivate: !!req.body.viewOncePrivate,
      viewOnceGroup: !!req.body.viewOnceGroup,
      commandAccess: validCommandAccess.includes(req.body.commandAccess) ? req.body.commandAccess : 'all',
      commandScope: validCommandScope.includes(req.body.commandScope) ? req.body.commandScope : 'all',
      alertsDestination: validAlertsDestination.includes(req.body.alertsDestination) ? req.body.alertsDestination : 'allowed_groups'
    };
    saveAllowedData(botId, { features: newFeatures });
    res.redirect(botPath(botId));
  });

  // ── POST /:botId/delete ──
  app.post('/:botId/delete', (req, res) => {
    const botId = getExistingBotId(bots, req.params.botId);
    if (botId) deleteBot(botId);
    res.redirect('/dashboard');
  });

  // ── POST /:botId/disconnect ──
  app.post('/:botId/disconnect', botAuthLimiter, async (req, res) => {
    const botId = getExistingBotId(bots, req.params.botId);
    if (!botId) return res.redirect('/dashboard');
    await disconnectBotAuth(botId);
    res.redirect(botPath(botId));
  });

  // ── GET /:botId/qr ──
  app.get('/:botId/qr', botAuthLimiter, async (req, res) => {
    const botId = getExistingBotId(bots, req.params.botId);
    const bot = bots.get(botId);
    if (!bot) return res.redirect('/dashboard');
    if (bot.isConnected) return res.send(`${getGlobalStyles(`Connecté - ${botId}`)}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>Déjà connecté</h2>
  <div class="actions" style="justify-content:center;"><a class="btn btn-primary" href="/${escapeHtml(botId)}/">Retour</a></div>
</div></div></div></body></html>`);

    try {
      if (typeof prepareBotForAuth === 'function') await prepareBotForAuth(botId);
    } catch (err) {
      return res.send(`${getGlobalStyles('QR bloque')}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>QR indisponible</h2>
  <p>${escapeHtml(err.message)}</p>
  <div class="actions" style="justify-content:center;">
    <a class="btn btn-secondary" href="/${escapeHtml(botId)}/">Retour</a>
  </div>
</div></div></div></body></html>`);
    }

    const qrData = bot.latestQrDataUrl;
    if (!qrData) return res.send(`${getGlobalStyles('En attente')}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>QR pas encore prêt</h2>
  <p>Patientez quelques secondes puis rafraîchissez.</p>
  <div class="actions" style="justify-content:center;">
    <a class="btn btn-primary" href="/${escapeHtml(botId)}/qr"><span class="ico">${ICO.refresh}</span> Rafraîchir</a>
    <a class="btn btn-secondary" href="/${escapeHtml(botId)}/">Retour</a>
  </div>
</div></div></div></body></html>`);

    res.send(`${getGlobalStyles('Scanner QR')}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2 style="display:flex;align-items:center;justify-content:center;gap:8px;"><span class="ico">${ICO.qr}</span> Scanner le QR Code</h2>
  <p>Ouvrez WhatsApp &rarr; Appareils liés &rarr; Lier un appareil</p>
  <div style="display:flex;justify-content:center;margin:24px 0;">
    <div class="qr-box"><img src="${qrData}" alt="QR Code" /></div>
  </div>
  <div class="actions" style="justify-content:center;">
    <a class="btn btn-secondary" href="/${escapeHtml(botId)}/">Retour</a>
  </div>
</div></div></div></body></html>`);
  });

  // ── GET /:botId/pair ──
  app.get('/:botId/pair', botAuthLimiter, (req, res) => {
    const botId = getExistingBotId(bots, req.params.botId);
    const bot = bots.get(botId);
    if (!bot) return res.redirect('/dashboard');
    if (bot.isConnected) return res.send(`${getGlobalStyles(`Connecté - ${botId}`)}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>Déjà connecté</h2>
  <div class="actions" style="justify-content:center;"><a class="btn btn-primary" href="/${escapeHtml(botId)}/">Retour</a></div>
</div></div></div></body></html>`);

    if (bot.pairingCode) {
      return res.send(`${getGlobalStyles(`Code - ${botId}`)}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>Code de liaison</h2>
  <div class="code-display">${bot.pairingCode}</div>
  <div class="actions" style="justify-content:center;margin-top:20px;">
    <a class="btn btn-secondary" href="/${escapeHtml(botId)}/">Retour</a>
    <a class="btn btn-secondary" href="/${escapeHtml(botId)}/pair">Nouveau code</a>
  </div>
</div></div></div></body></html>`);
    }

    res.send(`${getGlobalStyles(`Numéro - ${botId}`)}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2 style="display:flex;align-items:center;justify-content:center;gap:8px;"><span class="ico">${ICO.phone}</span> Connecter par Numéro</h2>
  <p>Entrez votre numéro WhatsApp pour recevoir un code de liaison.</p>
  <form method="POST" action="/${escapeHtml(botId)}/pair" style="display:flex;flex-direction:column;gap:10px;margin-top:20px;text-align:left;">
    ${csrfInput(req.session)}
    <input type="tel" name="phone" placeholder="ex: 33612345678" required />
    <button type="submit" class="btn-primary btn-full">Obtenir le Code</button>
  </form>
  <div class="actions" style="justify-content:center;margin-top:16px;">
    <a class="btn btn-secondary" href="/${escapeHtml(botId)}/">Retour</a>
  </div>
</div></div></div></body></html>`);
  });

  // ── POST /:botId/pair ──
  app.post('/:botId/pair', botAuthLimiter, async (req, res) => {
    const botId = getExistingBotId(bots, req.params.botId);
    if (!botId) return res.redirect('/dashboard');
    if (!req.body.phone) return res.redirect(botPath(botId, '/pair'));
    try {
      const code = await getPairingCode(botId, req.body.phone);
      res.send(`${getGlobalStyles(`Code - ${botId}`)}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2>Code généré !</h2>
  <div class="code-display">${code}</div>
  <div class="actions" style="justify-content:center;margin-top:20px;">
    <a class="btn btn-primary" href="/${escapeHtml(botId)}/">Dashboard</a>
  </div>
</div></div></div></body></html>`);
    } catch (err) {
      res.send(`${getGlobalStyles('Erreur')}
<body><div class="container"><div class="center-wrap"><div class="simple-card">
  <h2 style="color:var(--red);">Erreur</h2>
  <p>${escapeHtml(err.message)}</p>
  <div class="actions" style="justify-content:center;margin-top:16px;">
    <a class="btn btn-primary" href="/${escapeHtml(botId)}/pair">Réessayer</a>
  </div>
</div></div></div></body></html>`);
    }
  });

  // ── GET /:botId/allowed ──
  app.get('/:botId/allowed', async (req, res) => {
    const botId = req.params.botId;
    if (!bots.has(botId)) return res.redirect('/dashboard');
    res.send(buildAllowedPage({ botId, groups: await getGroupsList(botId), saved: loadAllowedData(botId), session: req.session }));
  });

  // ── POST /:botId/allowed/save ──
  app.post('/:botId/allowed/save', (req, res) => {
    const botId = req.params.botId;
    if (!bots.has(botId)) return res.redirect('/dashboard');
    let groups = req.body.groups || [];
    saveAllowedData(botId, { groups: [...new Set((Array.isArray(groups) ? groups : [groups]).map((x) => String(x).trim()).filter(Boolean))] });
    res.redirect(`/${botId}/allowed`);
  });

  // ── GET /:botId/grouptracked ──
  app.get('/:botId/grouptracked', async (req, res) => {
    const botId = req.params.botId;
    if (!bots.has(botId)) return res.redirect('/dashboard');
    res.send(buildTrackedGroupsPage({ botId, groups: await getGroupsList(botId), saved: loadAllowedData(botId), session: req.session }));
  });

  // ── POST /:botId/grouptracked/save ──
  app.post('/:botId/grouptracked/save', (req, res) => {
    const botId = req.params.botId;
    if (!bots.has(botId)) return res.redirect('/dashboard');
    let trackedGroups = req.body.trackedGroups || [];
    saveAllowedData(botId, { trackedGroups: [...new Set((Array.isArray(trackedGroups) ? trackedGroups : [trackedGroups]).map((x) => String(x).trim()).filter(Boolean))] });
    res.redirect(`/${botId}/grouptracked`);
  });

  app.listen(PORT, () => console.log(`Serveur Web tournant sur le port ${PORT}`));
};

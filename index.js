// Load environment variables from a local .env file if present (no dependency;
// requires Node >= 20.12). Must run before any config below is read.
try {
  const _fs = require('fs');
  const _envPath = require('path').join(__dirname, '.env');
  if (typeof process.loadEnvFile === 'function' && _fs.existsSync(_envPath)) {
    process.loadEnvFile(_envPath);
  }
} catch (e) { /* .env is optional */ }

const QRCode = require('qrcode');
const P = require('pino');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { execFileSync } = require('child_process');

const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = process.env.LOG_FILE
  ? (path.isAbsolute(process.env.LOG_FILE) ? process.env.LOG_FILE : path.join(__dirname, process.env.LOG_FILE))
  : path.join(LOG_DIR, 'server.log');

function formatLogArg(arg) {
  if (arg instanceof Error) return arg.stack || arg.message;
  if (typeof arg === 'string') return arg;
  return util.inspect(arg, { depth: 6, breakLength: 180 });
}

function installFileLogger(processName = 'index') {
  if (console.__fileLoggerInstalled) return;
  const original = {};
  for (const method of ['log', 'info', 'warn', 'error', 'debug']) {
    original[method] = console[method].bind(console);
  }

  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (err) { }

  for (const method of Object.keys(original)) {
    console[method] = (...args) => {
      const line = `${new Date().toISOString()} [${processName}] [${method.toUpperCase()}] ${args.map(formatLogArg).join(' ')}\n`;
      try { fs.appendFileSync(LOG_FILE, line, 'utf8'); } catch (err) { original.error('[LOGGER] write failed:', err.message); }
      original[method](...args);
    };
  }

  console.__fileLoggerInstalled = true;
  console.log(`[LOGGER] Logs saved to ${LOG_FILE}`);
}

installFileLogger('index');

// ===============================
// GLOBAL ERROR HANDLING (AJOUTÉ POUR ÉVITER LES CRASHS SOUDAINS)
// ===============================
process.on('uncaughtException', (err) => {
  console.error('🚨 [CRASH] Uncaught Exception:', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 [CRASH] Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Import Web Server Logic
const startWebServer = require('./web');

// Importation de votre nouveau fichier downloader.js
const { processLinksAndBroadcast } = require('./downloader');

// Assistant IA (commande .ask)
const { askAI, isConfigured: isAiConfigured } = require('./ai');

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
  downloadMediaMessage,
  WAMessageStubType
} = require('@whiskeysockets/baileys');

const PORT = process.env.PORT || 8080;
const SERVER_ROLE = String(process.env.SERVER_ROLE || 'railway').trim().toLowerCase();
const SERVER_NAME = String(process.env.SERVER_NAME || 'Serveur Railway').trim();
const WHATSAPP_ENABLED = !['0', 'false', 'no', 'off'].includes(
  String(process.env.WHATSAPP_ENABLED || 'true').trim().toLowerCase()
);
function resolveDataDir() {
  const configured = String(process.env.APP_DATA_DIR || process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || '').trim();
  if (!configured) return __dirname;
  return path.isAbsolute(configured) ? configured : path.join(__dirname, configured);
}

const DATA_DIR = resolveDataDir();
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (err) { }
function dataPath(fileName) { return path.join(DATA_DIR, fileName); }

const DELETED_CACHE_FOLDER = dataPath('deleted_cache');
const BOTS_FILE = dataPath('bots.json');
const COMMAND_PREFIX = String(process.env.COMMAND_PREFIX || '.').trim() || '.';
const DELETED_CACHE_MAX_AGE_DAYS = Number(process.env.DELETED_CACHE_MAX_AGE_DAYS || 7);
const DELETED_CACHE_CLEANUP_INTERVAL_MS = Number(process.env.DELETED_CACHE_CLEANUP_INTERVAL_MS || 6 * 60 * 60 * 1000);
const RESOURCE_ALERT_INTERVAL_MS = Number(process.env.RESOURCE_ALERT_INTERVAL_MS || 5 * 60 * 1000);
const RESOURCE_ALERT_COOLDOWN_MS = Number(process.env.RESOURCE_ALERT_COOLDOWN_MS || 30 * 60 * 1000);
const RESOURCE_ALERT_RAM_PERCENT = Number(process.env.RESOURCE_ALERT_RAM_PERCENT || 85);
const RESOURCE_ALERT_DISK_PERCENT = Number(process.env.RESOURCE_ALERT_DISK_PERCENT || 85);
const SPEEDTEST_DOWNLOAD_URL = String(process.env.SPEEDTEST_DOWNLOAD_URL || 'https://speed.cloudflare.com/__down?bytes=10000000').trim();
const SPEEDTEST_TIMEOUT_MS = Number(process.env.SPEEDTEST_TIMEOUT_MS || 20000);
const SPEEDTEST_MAX_BYTES = Number(process.env.SPEEDTEST_MAX_BYTES || 10 * 1024 * 1024);

// true = autoriser les groupes si cochés
const ALLOW_GROUPS = true;

// ===============================
// MULTI-BOT DYNAMIQUE
// ===============================
const bots = new Map();
const userFlows = new Map();

function loadBotsList() {
  try {
    const raw = fs.readFileSync(BOTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : ['bot1'];
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      fs.writeFileSync(BOTS_FILE, JSON.stringify(['bot1'], null, 2), 'utf8');
      return ['bot1'];
    }
    return ['bot1'];
  }
}

function saveBotsList() {
  const list = Array.from(bots.keys());
  fs.writeFileSync(BOTS_FILE, JSON.stringify(list, null, 2), 'utf8');
}

// Neutralizes any path-traversal / separator characters in a bot id before it is
// ever used to build a filesystem path. Allowed: letters, digits, _ and -.
function sanitizeBotId(botId) {
  return String(botId || '').trim().replace(/[^a-zA-Z0-9_-]/g, '_');
}

function initBotObject(botId) {
  const safeId = sanitizeBotId(botId);
  return {
    id: botId,
    AUTH_FOLDER: dataPath(`auth_info_${safeId}`),
    ALLOWED_FILE: dataPath(`allowed_${safeId}.json`),
    latestQrDataUrl: null,
    isConnected: false,
    currentConnectionState: 'starting',
    sock: null,
    isStarting: false,
    pairingCode: null,
    knownChats: new Map(),
    privateMessagesStore: new Map(),
    trackedGroupMessagesStore: new Map(),
    knownContactPhotos: new Map(),
    ownJids: new Set()  // Stores the bot's own JIDs (phone + LID) to skip self-updates
  };
}

const savedBotIds = loadBotsList();
savedBotIds.forEach(botId => {
  bots.set(botId, initBotObject(botId));
});

function addNewBot(botId) {
  const cleanId = sanitizeBotId(botId);
  if (!cleanId || bots.has(cleanId)) return false;

  const newBot = initBotObject(cleanId);
  bots.set(cleanId, newBot);
  saveBotsList();
  if (whatsappActive) startBot(newBot).catch(() => { });
  return true;
}

function deleteBot(botId) {
  const b = bots.get(botId);
  if (!b) return false;
  if (b.sock) {
    try { b.sock.logout(); } catch (e) { }
    try { b.sock.end(undefined); } catch (e) { }
  }
  bots.delete(botId);
  saveBotsList();
  clearAuthFolder(b);
  try { if (fs.existsSync(b.ALLOWED_FILE)) fs.rmSync(b.ALLOWED_FILE); } catch (e) { }
  return true;
}

async function disconnectBotAuth(botId) {
  try { // AJOUTÉ : Protection contre les erreurs de déconnexion
    const b = bots.get(botId);
    if (!b) return false;
    if (b.sock) {
      try { await b.sock.logout(); } catch (e) { clearAuthFolder(b); }
    } else {
      clearAuthFolder(b);
    }
    return true;
  } catch (err) { console.error('Erreur disconnectBotAuth:', err); return false; } // AJOUTÉ
}

// ===============================
// PAIRING CODE (NUMERO)
// ===============================
async function getPairingCode(botId, phoneNumber) {
  const bot = bots.get(botId);
  if (!bot) throw new Error("Bot introuvable.");
  if (!bot.sock) await prepareBotForAuth(botId);
  if (!bot.sock) throw new Error("Le bot n'est pas encore initialise.");
  if (bot.isConnected) throw new Error("Le bot est déjà connecté.");

  const cleanPhone = phoneNumber.replace(/\D/g, '');
  const code = await bot.sock.requestPairingCode(cleanPhone);
  bot.pairingCode = code;
  return code;
}

// ===============================
// PERSISTENCE & OPTIONS (Par Bot)
// ===============================
const defaultFeatures = {
  broadcast: true,
  antiDeletePrivate: true,
  antiDeleteGroup: true,
  statusForwarding: true,
  groupNotifications: true,
  commandAccess: 'all', // 'all', 'admin', 'owner'
  commandScope: 'all', // 'all', 'private_only', 'allowed_groups_only', 'private_and_allowed_groups'
  alertsDestination: 'allowed_groups', // 'allowed_groups', 'owner'
  adminNotifications: true,
  groupMetaNotifications: true,
  contactPhotoNotifications: true,
  viewOncePrivate: true,
  viewOnceGroup: true
};

function defaultAllowedData() {
  return { groups: [], trackedGroups: [], features: defaultFeatures };
}

function loadAllowedData(bot) {
  try {
    const file = typeof bot === 'string' ? dataPath(`allowed_${sanitizeBotId(bot)}.json`) : bot.ALLOWED_FILE;
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      groups: Array.isArray(parsed.groups) ? parsed.groups : [],
      trackedGroups: Array.isArray(parsed.trackedGroups) ? parsed.trackedGroups : [],
      features: { ...defaultFeatures, ...(parsed.features || {}) }
    };
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      const initial = defaultAllowedData();
      const file = typeof bot === 'string' ? dataPath(`allowed_${sanitizeBotId(bot)}.json`) : bot.ALLOWED_FILE;
      fs.writeFileSync(file, JSON.stringify(initial, null, 2), 'utf8');
      return initial;
    }
    return defaultAllowedData();
  }
}

function saveAllowedData(bot, data) {
  const file = typeof bot === 'string' ? dataPath(`allowed_${sanitizeBotId(bot)}.json`) : bot.ALLOWED_FILE;
  const current = loadAllowedData(bot);
  const clean = {
    groups: Array.isArray(data.groups) ? data.groups : current.groups,
    trackedGroups: Array.isArray(data.trackedGroups) ? data.trackedGroups : current.trackedGroups,
    features: { ...defaultFeatures, ...current.features, ...(data.features || {}) }
  };
  fs.writeFileSync(file, JSON.stringify(clean, null, 2), 'utf8');
}

function isAllowedGroup(bot, groupJid) { return loadAllowedData(bot).groups.includes(groupJid); }
function isTrackedGroup(bot, groupJid) { return loadAllowedData(bot).trackedGroups.includes(groupJid); }

// ===============================
// HELPERS
// ===============================

function unwrapMessageContent(msg) {
  if (!msg?.message) return {};
  let content = msg.message;
  for (let depth = 0; depth < 8; depth++) {
    const nested =
      content.deviceSentMessage?.message ||
      content.ephemeralMessage?.message ||
      content.documentWithCaptionMessage?.message ||
      content.viewOnceMessageV2?.message ||
      content.viewOnceMessage?.message ||
      content.viewOnceMessageV2Extension?.message;
    if (!nested || nested === content) break;
    content = nested;
  }
  return content;
}

function isViewOnceMessage(msg) {
  if (!msg?.message) return false;
  let content = msg.message;
  if (content.deviceSentMessage?.message) content = content.deviceSentMessage.message;
  if (content.ephemeralMessage?.message) content = content.ephemeralMessage.message;
  if (content.documentWithCaptionMessage?.message) content = content.documentWithCaptionMessage.message;
  const keys = Object.keys(content || {});
  if (keys.includes('viewOnceMessageV2') || keys.includes('viewOnceMessage') || keys.includes('viewOnceMessageV2Extension')) return true;
  if (content.imageMessage?.viewOnce || content.videoMessage?.viewOnce || content.audioMessage?.viewOnce) return true;
  return false;
}

/**
 * extractViewOnce — strips the view-once wrapper and sets viewOnce=false
 * so Baileys can forward it normally via sock.sendMessage({ forward: ... }).
 */
function extractViewOnce(msg) {
  if (!msg?.message) return null;
  let content = msg.message;

  if (content.deviceSentMessage?.message) content = content.deviceSentMessage.message;
  if (content.ephemeralMessage?.message) content = content.ephemeralMessage.message;
  if (content.documentWithCaptionMessage?.message) content = content.documentWithCaptionMessage.message;

  let inner = null;
  if (content.viewOnceMessageV2?.message) inner = content.viewOnceMessageV2.message;
  else if (content.viewOnceMessage?.message) inner = content.viewOnceMessage.message;
  else if (content.viewOnceMessageV2Extension?.message) inner = content.viewOnceMessageV2Extension.message;
  else if (content.imageMessage?.viewOnce) inner = content;
  else if (content.videoMessage?.viewOnce) inner = content;
  else if (content.audioMessage?.viewOnce) inner = content;

  if (!inner) return null;

  const innerCopy = JSON.parse(JSON.stringify(inner));
  if (innerCopy.imageMessage) innerCopy.imageMessage.viewOnce = false;
  if (innerCopy.videoMessage) innerCopy.videoMessage.viewOnce = false;
  if (innerCopy.audioMessage) innerCopy.audioMessage.viewOnce = false;

  return {
    key: { ...msg.key, fromMe: false },
    message: innerCopy,
    messageTimestamp: msg.messageTimestamp,
    pushName: msg.pushName,
  };
}

function getTextFromMessage(msg) {
  const content = unwrapMessageContent(msg);
  return (content.conversation || content.extendedTextMessage?.text || content.imageMessage?.caption || content.videoMessage?.caption || content.documentMessage?.caption || '');
}

function isGroupJid(jid = '') { return jid.endsWith('@g.us'); }

function getOwnerJid(bot) {
  if (!bot.sock || !bot.sock.user || !bot.sock.user.id) return null;
  return bot.sock.user.id.split(':')[0] + '@s.whatsapp.net';
}

function getTargetJids(bot, saved) {
  let targets = [];
  if (saved.features.alertsDestination === 'owner') {
    const owner = getOwnerJid(bot);
    if (owner) targets.push(owner);
  } else {
    if (ALLOW_GROUPS && Array.isArray(saved.groups)) targets = saved.groups;
  }
  return targets;
}

function commandName(name) {
  return `${COMMAND_PREFIX}${name}`;
}

function parsePrefixedCommand(text = '') {
  const value = String(text || '').trim();
  if (!value.startsWith(COMMAND_PREFIX)) return '';
  const commandText = value.slice(COMMAND_PREFIX.length).trim();
  return commandText.split(/\s+/)[0].toLowerCase();
}

function parsePrefixedCommandArgs(text = '') {
  const value = String(text || '').trim();
  if (!value.startsWith(COMMAND_PREFIX)) return '';
  const commandText = value.slice(COMMAND_PREFIX.length).trim();
  const firstSpace = commandText.search(/\s/);
  return firstSpace === -1 ? '' : commandText.slice(firstSpace).trim();
}

function buildHelpText() {
  return [
    '📘 *AIDE DU BOT*',
    '',
    `Les commandes commencent par *${COMMAND_PREFIX}* :`,
    `• *${commandName('ping')}* : pour vérifier si je suis là`,
    `• *${commandName('stats')}* : pour voir l'état du serveur`,
    `• *${commandName('servers')}* : pour voir le statut du serveur autonome`,
    `• *${commandName('uptime')}* : pour voir le temps de fonctionnement`,
    `• *${commandName('reboot')}* : pour redémarrer le système (Propriétaire)`,
    `• *${commandName('bots')}* : menu de gestion des bots (Propriétaire)`,
    `• *${commandName('test')}* : pour lancer un test de vitesse de connexion`,
    `• *${commandName('u')} <url>* : télécharger une vidéo (Instagram, TikTok, Facebook, YouTube, X)`,
    `• *${commandName('ask')} <question>* : poser une question à l'assistant IA`,
    `• *${commandName('menu')}* : pour réafficher cette liste`,
    `• *${commandName('exit')}* : annuler une action en cours`
  ].join('\n');
}

function buildMenuText() {
  return [
    '🤖 *MENU PRINCIPAL*',
    '',
    `🔹 *${commandName('ping')}*`,
    `🔹 *${commandName('stats')}*`,
    `🔹 *${commandName('servers')}*`,
    `🔹 *${commandName('uptime')}* ⏱️`,
    `🔹 *${commandName('test')}* 🚀`,
    `🔹 *${commandName('u')} <url>* 🎬`,
    `🔹 *${commandName('ask')} <question>* 🤖`,
    `🔹 *${commandName('reboot')}* ⚙️`,
    `🔹 *${commandName('bots')}* ⚙️`,
    `🔹 *${commandName('help')}*`,
    `🔹 *${commandName('menu')}*`,
    `🔹 *${commandName('exit')}* ❌`
  ].join('\n');
}

function ensureDeletedCacheFolder() {
  try { if (!fs.existsSync(DELETED_CACHE_FOLDER)) fs.mkdirSync(DELETED_CACHE_FOLDER, { recursive: true }); } catch (err) { }
}

function clearAuthFolder(bot) {
  try { if (fs.existsSync(bot.AUTH_FOLDER)) fs.rmSync(bot.AUTH_FOLDER, { recursive: true, force: true }); } catch (err) { }
}

async function restartBot(bot, { clearAuth = false } = {}) {
  try { // AJOUTÉ : Protection asynchrone
    if (clearAuth) clearAuthFolder(bot);
    bot.latestQrDataUrl = null;
    bot.pairingCode = null;
    bot.isConnected = false;
    bot.currentConnectionState = 'restarting';
    setTimeout(() => { startBot(bot).catch(() => { }); }, 2000);
  } catch (err) { console.error('Erreur restartBot:', err); } // AJOUTÉ
}

function rememberGroup(bot, jid, subject = '') {
  if (!jid || !isGroupJid(jid)) return;
  bot.knownChats.set(jid, { jid, name: subject || jid, type: 'group' });
}

function getKnownGroupName(bot, jid = '') { return bot.knownChats.get(jid)?.name || jid; }

async function getGroupsList(bot) {
  try {
    if (!bot.sock || !bot.isConnected) return [];
    const groupsObj = await bot.sock.groupFetchAllParticipating();
    const groups = Object.values(groupsObj || {}).map((g) => ({ jid: g.id, name: g.subject || g.id, type: 'group' }));
    for (const g of groups) rememberGroup(bot, g.jid, g.name);
    groups.sort((a, b) => a.name.localeCompare(b.name));
    return groups;
  } catch (err) { return []; }
}

async function sendBotsMenu(sock, jid) {
  try { // AJOUTÉ : Protection si la socket se déconnecte pendant l'envoi
    let listStr = "";
    for (const [id, b] of bots.entries()) {
      const status = b.isConnected ? '🟢 Connecté' : '🔴 Déconnecté';
      listStr += `- *${id}* [${status}]\n`;
    }

    const menu = `🤖 *Gestionnaire Multi-Bots*\n\n📋 *Vos bots actuels :*\n${listStr}\n*Que voulez-vous faire ?*\n*1.* ➕ Ajouter un bot\n*2.* 🗑️ Supprimer un bot\n*3.* 🔐 Connecter un bot (QR/Code)\n*4.* 🔌 Déconnecter un bot\n\n💡 _Astuce : Tapez *exit* ou *${commandName('exit')}* à tout moment pour annuler._\n\n_Répondez par un chiffre (1-4)_`;
    await sock.sendMessage(jid, { text: menu });
  } catch (err) { console.error('Erreur sendBotsMenu:', err); } // AJOUTÉ
}

function getHostDiskUsage() {
  let diskInfo = { percent: 'N/A', used: 'N/A', total: 'N/A' };
  try {
    const lines = execFileSync('df', ['-B1', '/'], { encoding: 'utf8' }).trim().split(/\r?\n/);
    const df = String(lines[lines.length - 1] || '').trim().replace(/\s+/g, ' ').split(' ');
    if (df.length >= 5) {
      diskInfo.total = (parseInt(df[1]) / (1024 ** 3)).toFixed(2) + ' GB';
      diskInfo.used = (parseInt(df[2]) / (1024 ** 3)).toFixed(2) + ' GB';
      diskInfo.percent = df[4];
      return diskInfo;
    }
  } catch (e) { }
  return diskInfo;
}

function getContainerRamUsage() {
  const MAX_RAM_BYTES = 0.5 * 1024 * 1024 * 1024;
  let usedRamBytes = process.memoryUsage().rss;
  try {
    if (fs.existsSync('/sys/fs/cgroup/memory/memory.usage_in_bytes')) usedRamBytes = parseInt(fs.readFileSync('/sys/fs/cgroup/memory/memory.usage_in_bytes', 'utf8'));
    else if (fs.existsSync('/sys/fs/cgroup/memory.current')) usedRamBytes = parseInt(fs.readFileSync('/sys/fs/cgroup/memory.current', 'utf8'));
  } catch (e) { }
  return { percent: `${((usedRamBytes / MAX_RAM_BYTES) * 100).toFixed(1)}%`, used: `${(usedRamBytes / (1024 ** 2)).toFixed(1)} MB`, total: `512 MB` };
}

function getContainerDiskUsage() {
  let diskInfo = { percent: 'N/A', used: 'N/A', total: '1024 MB' };
  const MAX_DISK_BYTES = 1 * 1024 * 1024 * 1024;
  try {
    const duOutput = execFileSync('du', ['-sb', __dirname], { encoding: 'utf8' }).trim().split(/\s+/);
    if (duOutput.length > 0) {
      const usedBytes = parseInt(duOutput[0], 10);
      diskInfo.used = `${(usedBytes / (1024 ** 2)).toFixed(1)} MB`;
      diskInfo.percent = `${((usedBytes / MAX_DISK_BYTES) * 100).toFixed(1)}%`;
    }
  } catch (e) { }
  return diskInfo;
}

function parsePercent(value) {
  const percent = parseFloat(String(value || '').replace('%', '').trim());
  return Number.isFinite(percent) ? percent : 0;
}

function formatBytes(bytes = 0) {
  const value = Math.max(0, Number(bytes) || 0);
  if (value >= 1024 ** 3) return `${(value / (1024 ** 3)).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / (1024 ** 2)).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${value} B`;
}

async function runDownloadSpeedTest() {
  const headerStart = Date.now();
  const response = await axios.get(SPEEDTEST_DOWNLOAD_URL, {
    responseType: 'stream',
    timeout: Math.max(3000, SPEEDTEST_TIMEOUT_MS || 20000),
    maxRedirects: 5,
    headers: { 'User-Agent': 'Mozilla/5.0 WhatsAppBot-Speedtest' },
    validateStatus: (status) => status >= 200 && status < 400
  });
  const latencyMs = Date.now() - headerStart;
  const stream = response.data;
  const downloadStart = Date.now();
  const maxBytes = Math.max(1024 * 1024, SPEEDTEST_MAX_BYTES || 10 * 1024 * 1024);
  let bytes = 0;

  await new Promise((resolve, reject) => {
    stream.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes >= maxBytes) stream.destroy();
    });
    stream.on('end', resolve);
    stream.on('close', resolve);
    stream.on('error', reject);
  });

  const durationSeconds = Math.max((Date.now() - downloadStart) / 1000, 0.001);
  return {
    downloadMbps: ((bytes * 8) / durationSeconds / 1000000).toFixed(2),
    latencyMs,
    bytes,
    durationSeconds: durationSeconds.toFixed(2),
    url: SPEEDTEST_DOWNLOAD_URL
  };
}

function cleanupDeletedCache() {
  try {
    ensureDeletedCacheFolder();
    const maxAgeMs = Math.max(1, DELETED_CACHE_MAX_AGE_DAYS || 7) * 24 * 60 * 60 * 1000;
    const cutoff = Date.now() - maxAgeMs;
    let deleted = 0;

    for (const entry of fs.readdirSync(DELETED_CACHE_FOLDER, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const filePath = path.join(DELETED_CACHE_FOLDER, entry.name);
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs < cutoff) {
        fs.rmSync(filePath, { force: true });
        deleted++;
      }
    }

    if (deleted) console.log(`[CACHE] Deleted ${deleted} old anti-delete cache file(s).`);
    return deleted;
  } catch (err) {
    console.error('[CACHE] cleanup error:', err.message);
    return 0;
  }
}

function startDeletedCacheCleanup() {
  const intervalMs = Math.max(60 * 60 * 1000, DELETED_CACHE_CLEANUP_INTERVAL_MS || 6 * 60 * 60 * 1000);
  setTimeout(cleanupDeletedCache, 15000);
  setInterval(cleanupDeletedCache, intervalMs);
}

function buildMessageStoreKey(messageId) { return String(messageId || '').trim(); }
function buildTrackedGroupMessageStoreKey(groupJid, messageId) { return `${String(groupJid || '').trim()}:${String(messageId || '').trim()}`; }
function getReadableTimestamp(ts) { try { let ms = Number(ts || 0); if (ms > 0 && ms < 1000000000000) ms *= 1000; return new Date(ms).toLocaleString('fr-FR'); } catch (err) { return 'date inconnue'; } }
function detectMediaInfo(msg) {
  const content = unwrapMessageContent(msg);
  if (!content) return { hasMedia: false, mediaType: 'text', mimeType: '', extension: '.bin' };
  if (content.imageMessage) return { hasMedia: true, mediaType: 'image', mimeType: content.imageMessage.mimetype || 'image/jpeg', extension: '.jpg' };
  if (content.videoMessage) return { hasMedia: true, mediaType: 'video', mimeType: content.videoMessage.mimetype || 'video/mp4', extension: '.mp4' };
  if (content.ptvMessage) return { hasMedia: true, mediaType: 'video', mimeType: content.ptvMessage.mimetype || 'video/mp4', extension: '.mp4', ptv: true };
  if (content.audioMessage) {
    const mimeType = content.audioMessage.mimetype || 'audio/ogg; codecs=opus';
    const extension = mimeType.includes('mpeg') ? '.mp3' : mimeType.includes('mp4') ? '.m4a' : '.ogg';
    return { hasMedia: true, mediaType: 'audio', mimeType, extension, ptt: Boolean(content.audioMessage.ptt) };
  }
  if (content.stickerMessage) return { hasMedia: true, mediaType: 'sticker', mimeType: content.stickerMessage.mimetype || 'image/webp', extension: '.webp' };
  if (content.documentMessage) {
    const fileName = content.documentMessage.fileName || '';
    return { hasMedia: true, mediaType: 'document', mimeType: content.documentMessage.mimetype || 'application/octet-stream', extension: path.extname(fileName) || '.bin', fileName };
  }
  return { hasMedia: false, mediaType: 'text', mimeType: '', extension: '.bin' };
}

function buildRecoveredMessage(msg) {
  try {
    const content = unwrapMessageContent(msg);
    const clonedContent = typeof structuredClone === 'function'
      ? structuredClone(content)
      : JSON.parse(JSON.stringify(content));
    return {
      key: { ...msg.key, fromMe: false },
      message: clonedContent,
      messageTimestamp: msg.messageTimestamp,
      pushName: msg.pushName
    };
  } catch (err) {
    console.error('[ANTI-DELETE] Could not preserve original message:', err.message);
    return null;
  }
}

function shouldForwardRecoveredMessage(msg, mediaInfo) {
  if (mediaInfo.hasMedia) return false;
  const content = unwrapMessageContent(msg);
  return Boolean(content && !content.conversation && !content.extendedTextMessage);
}

async function downloadMediaToFile(bot, msg, prefix = 'media') {
  try {
    if (!bot.sock) return null;
    const info = detectMediaInfo(msg);
    if (!info.hasMedia) return null;
    ensureDeletedCacheFolder();
    const buffer = await downloadMediaMessage(msg, 'buffer', {}, { logger: P({ level: 'silent' }), reuploadRequest: bot.sock.updateMediaMessage });
    if (!buffer || !Buffer.isBuffer(buffer)) return null;
    const messageId = msg?.key?.id || `msg_${Date.now()}`;
    const fileName = `${prefix}_${String(messageId).replace(/[^a-zA-Z0-9_-]/g, '_')}${info.extension}`;
    const filePath = path.join(DELETED_CACHE_FOLDER, fileName);
    fs.writeFileSync(filePath, buffer);
    return {
      filePath,
      fileName,
      mediaType: info.mediaType,
      mimeType: info.mimeType,
      originalFileName: info.fileName || fileName,
      ptt: Boolean(info.ptt),
      ptv: Boolean(info.ptv),
      buffer
    };
  } catch (err) {
    console.error(`[ANTI-DELETE] Media cache failed for ${msg?.key?.id || 'unknown message'}:`, err.message);
    return null;
  }
}

function extractDeletedMessageKey(msg) {
  const protocol = msg?.message?.protocolMessage;
  const key = protocol?.key;
  if (!key?.id) return null;
  return { jid: key.remoteJid || msg?.key?.remoteJid || '', jidAlt: key.remoteJidAlt || msg?.key?.remoteJidAlt || '', id: key.id, participant: key.participant || '' };
}

async function sendMediaIfExists(bot, targetJid, deletedInfo) {
  try {
    if (!deletedInfo?.hasMedia || !deletedInfo?.mediaPath || !fs.existsSync(deletedInfo.mediaPath)) return false;
    const fileBuffer = fs.readFileSync(deletedInfo.mediaPath);
    if (deletedInfo.mediaType === 'image') await bot.sock.sendMessage(targetJid, { image: fileBuffer });
    else if (deletedInfo.mediaType === 'video') await bot.sock.sendMessage(targetJid, { video: fileBuffer, ptv: Boolean(deletedInfo.ptv) });
    else if (deletedInfo.mediaType === 'audio') await bot.sock.sendMessage(targetJid, { audio: fileBuffer, mimetype: deletedInfo.mimeType || 'audio/ogg; codecs=opus', ptt: Boolean(deletedInfo.ptt) });
    else if (deletedInfo.mediaType === 'sticker') await bot.sock.sendMessage(targetJid, { sticker: fileBuffer });
    else if (deletedInfo.mediaType === 'document') await bot.sock.sendMessage(targetJid, { document: fileBuffer, mimetype: deletedInfo.mimeType || 'application/octet-stream', fileName: deletedInfo.mediaFileName || 'deleted-file' });
    else return false;
    return true;
  } catch (err) {
    console.error(`[ANTI-DELETE] Could not resend ${deletedInfo?.mediaType || 'media'} to ${targetJid}:`, err.message);
    return false;
  }
}

async function sendRecoveredMessage(bot, targetJid, deletedInfo) {
  if (deletedInfo?.mediaCachePromise) {
    try { await deletedInfo.mediaCachePromise; } catch (err) { }
  }
  const mediaSent = await sendMediaIfExists(bot, targetJid, deletedInfo);
  const needsFallback = (deletedInfo?.hasMedia && !mediaSent) || deletedInfo?.forwardOriginal;
  if (!needsFallback || !deletedInfo?.recoveredMessage) return;

  try {
    await bot.sock.sendMessage(targetJid, { forward: deletedInfo.recoveredMessage });
  } catch (err) {
    console.error(`[ANTI-DELETE] Could not forward recovered message to ${targetJid}:`, err.message);
  }
}

function startDeletedMediaCache(bot, msg, prefix, deletedInfo) {
  if (!deletedInfo?.hasMedia) return;
  deletedInfo.mediaCachePromise = downloadMediaToFile(bot, msg, prefix)
    .then((savedMedia) => {
      if (!savedMedia) return null;
      deletedInfo.mediaPath = savedMedia.filePath || '';
      deletedInfo.mediaFileName = savedMedia.originalFileName || savedMedia.fileName || '';
      deletedInfo.ptt = Boolean(savedMedia.ptt || deletedInfo.ptt);
      deletedInfo.ptv = Boolean(savedMedia.ptv || deletedInfo.ptv);
      return savedMedia;
    })
    .finally(() => {
      deletedInfo.mediaCachePromise = null;
    });
}

async function savePrivateMessage(bot, msg) {
  try { // AJOUTÉ : Protection écriture Map
    const id = msg?.key?.id || '';
    if (!id) return;
    const storeKey = buildMessageStoreKey(id);
    const mediaInfo = detectMediaInfo(msg);
    const deletedInfo = {
      jid: msg?.key?.remoteJid || '', jidAlt: msg?.key?.remoteJidAlt || '', id, senderName: msg?.pushName || 'Nom inconnu', text: getTextFromMessage(msg), timestamp: msg?.messageTimestamp || Math.floor(Date.now() / 1000),
      mediaType: mediaInfo.mediaType, mimeType: mediaInfo.mimeType, mediaPath: '', mediaFileName: mediaInfo.fileName || '',
      hasMedia: mediaInfo.hasMedia, ptt: Boolean(mediaInfo.ptt), ptv: Boolean(mediaInfo.ptv),
      recoveredMessage: buildRecoveredMessage(msg), forwardOriginal: shouldForwardRecoveredMessage(msg, mediaInfo)
    };
    bot.privateMessagesStore.set(storeKey, deletedInfo);
    startDeletedMediaCache(bot, msg, 'private', deletedInfo);
  } catch (err) { console.error('Erreur savePrivateMessage:', err); } // AJOUTÉ
}

async function sendDeletedPrivateMessageReport(bot, originalChatJid, deletedInfo) {
  const saved = loadAllowedData(bot);
  const targetJids = getTargetJids(bot, saved);
  if (targetJids.length === 0 || !bot.sock || !bot.isConnected) return;

  const report = ['🚨 *Message privé supprimé détecté*', '', `👤 *Nom:* ${deletedInfo.senderName}`, `📱 *Chat privé:* ${originalChatJid || 'inconnu'}`, `🕒 *Heure:* ${getReadableTimestamp(deletedInfo.timestamp)}`, `📎 *Média:* ${deletedInfo.hasMedia ? deletedInfo.mediaType : 'aucun'}`, '', '📝 *Contenu du message:*', deletedInfo.text ? deletedInfo.text : '[aucun texte]'].join('\n');
  for (const targetJid of targetJids) {
    try { await bot.sock.sendMessage(targetJid, { text: report }); await sendRecoveredMessage(bot, targetJid, deletedInfo); } catch (err) { console.error(`[ANTI-DELETE] Private deletion report failed for ${targetJid}:`, err.message); }
  }
}

async function saveTrackedGroupMessage(bot, msg) {
  try { // AJOUTÉ : Protection écriture Map de groupe
    const groupJid = msg?.key?.remoteJid || '';
    const messageId = msg?.key?.id || '';
    if (!groupJid || !messageId || !isTrackedGroup(bot, groupJid)) return;
    const storeKey = buildTrackedGroupMessageStoreKey(groupJid, messageId);
    const mediaInfo = detectMediaInfo(msg);
    const deletedInfo = {
      groupJid, groupName: getKnownGroupName(bot, groupJid), messageId, senderParticipant: msg?.key?.participant || msg?.participant || 'participant inconnu', senderName: msg?.pushName || 'Nom inconnu', text: getTextFromMessage(msg), timestamp: msg?.messageTimestamp || Math.floor(Date.now() / 1000),
      mediaType: mediaInfo.mediaType, mimeType: mediaInfo.mimeType, mediaPath: '', mediaFileName: mediaInfo.fileName || '',
      hasMedia: mediaInfo.hasMedia, ptt: Boolean(mediaInfo.ptt), ptv: Boolean(mediaInfo.ptv),
      recoveredMessage: buildRecoveredMessage(msg), forwardOriginal: shouldForwardRecoveredMessage(msg, mediaInfo)
    };
    bot.trackedGroupMessagesStore.set(storeKey, deletedInfo);
    startDeletedMediaCache(bot, msg, 'group', deletedInfo);
  } catch (err) { console.error('Erreur saveTrackedGroupMessage:', err); } // AJOUTÉ
}

async function sendDeletedTrackedGroupMessageReport(bot, deletedInfo) {
  const saved = loadAllowedData(bot);
  const targetJids = getTargetJids(bot, saved);
  if (targetJids.length === 0 || !bot.sock || !bot.isConnected) return;

  const report = ['🚨 *Message supprimé dans un groupe tracké*', '', `👥 *Groupe:* ${deletedInfo.groupName}`, `👤 *Auteur:* ${deletedInfo.senderName}`, `📱 *Participant:* ${deletedInfo.senderParticipant}`, `🕒 *Heure:* ${getReadableTimestamp(deletedInfo.timestamp)}`, `📎 *Média:* ${deletedInfo.hasMedia ? deletedInfo.mediaType : 'aucun'}`, '', '📝 *Contenu du message:*', deletedInfo.text ? deletedInfo.text : '[aucun texte]'].join('\n');
  for (const targetJid of targetJids) {
    try { await bot.sock.sendMessage(targetJid, { text: report }); await sendRecoveredMessage(bot, targetJid, deletedInfo); } catch (err) { console.error(`[ANTI-DELETE] Group deletion report failed for ${targetJid}:`, err.message); }
  }
}

async function recoverDeletedMessage(bot, deletedKey) {
  const messageId = deletedKey?.id || '';
  const chatJid = deletedKey?.jid || deletedKey?.remoteJid || '';
  const chatJidAlt = deletedKey?.jidAlt || deletedKey?.remoteJidAlt || '';
  if (!messageId) return false;

  const saved = loadAllowedData(bot);
  const groupJid = isGroupJid(chatJid) ? chatJid : (isGroupJid(chatJidAlt) ? chatJidAlt : '');

  if (groupJid) {
    if (!saved.features.antiDeleteGroup || !isTrackedGroup(bot, groupJid)) return false;
    const storeKey = buildTrackedGroupMessageStoreKey(groupJid, messageId);
    const deletedInfo = bot.trackedGroupMessagesStore.get(storeKey);
    if (!deletedInfo) return false;
    bot.trackedGroupMessagesStore.delete(storeKey);
    await sendDeletedTrackedGroupMessageReport(bot, deletedInfo);
    return true;
  }

  if (!saved.features.antiDeletePrivate) return false;
  const storeKey = buildMessageStoreKey(messageId);
  const deletedInfo = bot.privateMessagesStore.get(storeKey);
  if (!deletedInfo) return false;
  bot.privateMessagesStore.delete(storeKey);
  await sendDeletedPrivateMessageReport(bot, deletedInfo.jidAlt || deletedInfo.jid || chatJidAlt || chatJid || 'chat inconnu', deletedInfo);
  return true;
}

function canUseCommandsInThisChat(bot, jid, saved, groupMessage, privateMessage) {
  const scope = saved.features.commandScope || 'all';

  if (scope === 'all') return true;
  if (scope === 'private_only') return privateMessage;
  if (scope === 'allowed_groups_only') return groupMessage && isAllowedGroup(bot, jid);
  if (scope === 'private_and_allowed_groups') return privateMessage || (groupMessage && isAllowedGroup(bot, jid));

  return true;
}

// ===============================
// ACTIVE / STANDBY SERVERS
// ===============================
let whatsappActive = false;
const resourceAlertState = {
  ram: { isHigh: false, lastSentAt: 0 },
  disk: { isHigh: false, lastSentAt: 0 }
};

function summarizePeerStatus(status = {}) {
  return {
    serverName: status.serverName || '',
    role: status.role || '',
    port: status.port || '',
    whatsappActive: Boolean(status.whatsappActive),
    uptimeSeconds: status.uptimeSeconds || 0,
    bots: Array.isArray(status.bots)
      ? status.bots.map((bot) => ({
        id: bot.id || '',
        isConnected: Boolean(bot.isConnected),
        state: bot.state || ''
      }))
      : []
  };
}

function getInstanceStatus() {
  return {
    ok: true,
    serverName: SERVER_NAME,
    role: SERVER_ROLE,
    port: PORT,
    whatsappActive,
    uptimeSeconds: Math.floor(process.uptime()),
    peer: null,
    bots: Array.from(bots.values()).map((bot) => ({
      id: bot.id,
      isConnected: bot.isConnected,
      state: bot.currentConnectionState
    }))
  };
}

// Friendly server names (no "main"/"backup" in user-facing text).
function roleLabel(role) {
  return 'Serveur Railway';
}

function formatDuration(seconds = 0) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const parts = [];

  if (days) parts.push(`${days}j`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  if (!parts.length) parts.push(`${secs}s`);

  return parts.join(' ');
}

function formatStatusDate(value) {
  if (!value) return 'jamais';
  try {
    return new Date(value).toLocaleString('fr-FR');
  } catch (err) {
    return String(value);
  }
}

function countConnectedBots(status = {}) {
  return Array.isArray(status.bots) ? status.bots.filter((bot) => bot.isConnected).length : 0;
}

function formatBotsLine(status = {}) {
  const botCount = Array.isArray(status.bots) ? status.bots.length : 0;
  if (!botCount) return '- Bots: aucun';
  return `- Bots: ${countConnectedBots(status)}/${botCount} connecte(s)`;
}

function formatServerStatusBlock(label, status = {}, extraLines = []) {
  if (!status || !status.ok && !status.serverName && !status.role) {
    return [`*${label}*`, '- Etat: inconnu', ...extraLines].join('\n');
  }

  return [
    `*${label}*`,
    `- Serveur: ${roleLabel(status.role)}`,
    `- Port: ${status.port || 'n/a'}`,
    `- Mode WhatsApp: ${status.whatsappActive ? 'ACTIF' : 'EN VEILLE'}`,
    `- Uptime: ${formatDuration(status.uptimeSeconds)}`,
    formatBotsLine(status),
    ...extraLines
  ].join('\n');
}

async function buildServersStatusText() {
  const localStatus = getInstanceStatus();
  return [
    '🖥️ *Statut du serveur WhatsApp*',
    '',
    formatServerStatusBlock(`${roleLabel(SERVER_ROLE)} (ce serveur)`, localStatus, [
      '- Mode: autonome',
      '- Lien avec un serveur principal: aucun'
    ]),
    '',
    'Ce serveur fonctionne seul et ne contacte aucun serveur principal.'
  ].join('\n');
}

function startAllBots(reason = 'manual') {
  if (whatsappActive) return;
  whatsappActive = true;
  console.log(`[HA] ${SERVER_NAME} is ACTIVE. reason=${reason}`);
  for (const bot of bots.values()) {
    startBot(bot).catch((err) => { console.error('Erreur demarrage bot loop:', err); });
  }
}

function stopAllBots(reason = 'standby') {
  if (!whatsappActive) return;
  whatsappActive = false;
  console.log(`[HA] ${SERVER_NAME} is STANDBY. reason=${reason}`);
  for (const bot of bots.values()) {
    bot.isConnected = false;
    bot.currentConnectionState = 'standby';
    bot.latestQrDataUrl = null;
    bot.pairingCode = null;
    try { if (bot.sock) bot.sock.end(undefined); } catch (err) { }
    bot.sock = null;
  }
}

async function prepareBotForAuth(botId) {
  const bot = bots.get(botId);
  if (!bot) throw new Error('Bot introuvable.');
  if (bot.sock || bot.isConnected) return bot;

  if (!whatsappActive) {
    whatsappActive = true;
    console.log(`[HA] ${SERVER_NAME} is ACTIVE. reason=manual-auth`);
  }

  await startBot(bot);
  return bot;
}

// System alerts (HA / resources) are queued when they cannot be delivered yet
// (no connected bot, e.g. standby or mid-takeover) and flushed once a bot connects.
const pendingServerAlerts = [];
const PENDING_ALERT_TTL_MS = Number(process.env.PENDING_ALERT_TTL_MS || 60 * 60 * 1000);
const PENDING_ALERT_MAX = 50;

function enqueueServerAlert(message) {
  const firstLine = String(message).split('\n')[0];
  const expiresAt = Date.now() + PENDING_ALERT_TTL_MS;
  const existing = pendingServerAlerts.find((a) => a.firstLine === firstLine);
  if (existing) { existing.message = message; existing.expiresAt = expiresAt; return; }
  pendingServerAlerts.push({ message, firstLine, expiresAt });
  while (pendingServerAlerts.length > PENDING_ALERT_MAX) pendingServerAlerts.shift();
}

async function flushPendingServerAlerts() {
  if (!pendingServerAlerts.length) return;
  const now = Date.now();
  const queue = pendingServerAlerts.splice(0, pendingServerAlerts.length);
  for (const item of queue) {
    if (item.expiresAt < now) continue; // drop stale alerts
    const sent = await sendServerAlert(item.message);
    if (!sent) pendingServerAlerts.push(item); // requeue if still undeliverable
  }
}

async function sendServerAlert(message) {
  let sent = 0;
  const sentTargets = new Set();
  for (const bot of bots.values()) {
    if (!bot.sock || !bot.isConnected) continue;
    const saved = loadAllowedData(bot);
    let targetJids = getTargetJids(bot, saved);
    // Fallback: if no group/owner target is configured, alert the linked account itself,
    // so system alerts are never silently dropped.
    if (!targetJids || targetJids.length === 0) {
      const owner = getOwnerJid(bot);
      targetJids = owner ? [owner] : [];
    }
    for (const targetJid of targetJids) {
      if (sentTargets.has(targetJid)) continue;
      try {
        await bot.sock.sendMessage(targetJid, { text: message });
        sentTargets.add(targetJid);
        sent++;
      } catch (err) { }
    }
  }
  console.log(`[HA ALERT] sent=${sent} targets=${sentTargets.size} message=${String(message).split('\n')[0]}`);
  if (!sent) console.log(`[HA ALERT NOT SENT] ${message}`);
  return sent;
}

function notifyServerAlert(message, attemptsLeft = 6) {
  return sendServerAlert(message).then((sent) => {
    if (!sent) {
      enqueueServerAlert(message); // deliver when a bot next connects
      if (attemptsLeft > 0 && whatsappActive) {
        setTimeout(() => notifyServerAlert(message, attemptsLeft - 1), 10000);
      }
    }
    return sent;
  }).catch((err) => {
    console.error('[HA] alert error:', err.message);
    return 0;
  });
}

function shouldSendResourceAlert(key) {
  const state = resourceAlertState[key];
  const now = Date.now();
  if (!state.isHigh) return true;
  return now - state.lastSentAt >= Math.max(60000, RESOURCE_ALERT_COOLDOWN_MS || 30 * 60 * 1000);
}

function markResourceAlertSent(key, isHigh) {
  resourceAlertState[key].isHigh = isHigh;
  resourceAlertState[key].lastSentAt = Date.now();
}

async function maybeNotifyResourceAlert(key, label, percent, threshold, detail) {
  const state = resourceAlertState[key];
  if (percent >= threshold) {
    if (shouldSendResourceAlert(key)) {
      notifyServerAlert(`[${SERVER_NAME}] ${label} high: ${percent.toFixed(1)}% (limit ${threshold}%)\n${detail}`);
      markResourceAlertSent(key, true);
    }
    return;
  }

  if (state.isHigh) {
    notifyServerAlert(`[${SERVER_NAME}] ${label} recovered: ${percent.toFixed(1)}%`);
    markResourceAlertSent(key, false);
  }
}

async function checkResourceAlerts() {
  const ram = getContainerRamUsage();
  const disk = getContainerDiskUsage();
  const ramPercent = parsePercent(ram.percent);
  const diskPercent = parsePercent(disk.percent);

  await maybeNotifyResourceAlert('ram', 'RAM', ramPercent, RESOURCE_ALERT_RAM_PERCENT || 85, `${ram.used} / ${ram.total}`);
  await maybeNotifyResourceAlert('disk', 'Disk', diskPercent, RESOURCE_ALERT_DISK_PERCENT || 85, `${disk.used} / ${disk.total}`);
}

function startResourceMonitor() {
  const intervalMs = Math.max(60000, RESOURCE_ALERT_INTERVAL_MS || 5 * 60 * 1000);
  setTimeout(() => { checkResourceAlerts().catch((err) => console.error('[ALERT] resource check error:', err.message)); }, 20000);
  setInterval(() => { checkResourceAlerts().catch((err) => console.error('[ALERT] resource check error:', err.message)); }, intervalMs);
}

async function bootHighAvailability() {
  startDeletedCacheCleanup();
  startResourceMonitor();
  if (!WHATSAPP_ENABLED) {
    console.log('[HA] WhatsApp connections disabled by WHATSAPP_ENABLED.');
    return;
  }
  startAllBots('startup');
}

// ===============================
// START EXPRESS WEB SERVER
// ===============================

startWebServer({
  PORT,
  SERVER_NAME,
  SERVER_ROLE,
  bots,
  addNewBot,
  deleteBot,
  disconnectBotAuth,
  prepareBotForAuth,
  getPairingCode,
  loadAllowedData: (botId) => loadAllowedData(botId),
  saveAllowedData: (botId, data) => saveAllowedData(botId, data),
  getGroupsList: (botId) => getGroupsList(bots.get(botId)),
  getContainerRamUsage,
  getContainerDiskUsage,
  getHostDiskUsage,
  runDownloadSpeedTest,
  getInstanceStatus,
  restartProcess: () => {
    try { // AJOUTÉ : Protection du callback web
      console.log('🔄 Redémarrage demandé depuis l\'interface web...');
      setTimeout(() => { process.exit(1); }, 2000);
    } catch (err) { console.error(err); } // AJOUTÉ
  }
});

// ===============================
// BOT INSTANCE START
// ===============================

async function startBot(bot) {
  if (bot.isStarting) return;
  bot.isStarting = true;

  try {
    ensureDeletedCacheFolder();
    const { state, saveCreds } = await useMultiFileAuthState(bot.AUTH_FOLDER);
    const { version } = await fetchLatestBaileysVersion();

    bot.sock = makeWASocket({
      version,
      auth: state,
      logger: P({ level: 'silent' }),
      browser: ['Ubuntu', 'Chrome', '20.0.04']
    });

    bot.sock.ev.on('connection.update', async (update) => {
      try { // AJOUTÉ : Protection globale de l'événement de connexion
        const { connection, lastDisconnect, qr } = update;
        if (connection) bot.currentConnectionState = connection;
        if (qr) { try { bot.latestQrDataUrl = await QRCode.toDataURL(qr); } catch (err) { } }
        if (connection === 'open') {
          bot.isConnected = true;
          bot.latestQrDataUrl = null;
          bot.pairingCode = null;
          console.log(`✅ WhatsApp connecté (${bot.id})`);
          await getGroupsList(bot);
          flushPendingServerAlerts().catch((err) => console.error('[HA] flush alerts error:', err.message));

          // Store bot's own JIDs to reliably skip self-updates in contacts.update
          bot.ownJids = new Set();
          try {
            const ownPhoneJid = bot.sock?.user?.id || '';
            if (ownPhoneJid) {
              bot.ownJids.add(ownPhoneJid);
              const ownNum = ownPhoneJid.split('@')[0].split(':')[0];
              if (ownNum) bot.ownJids.add(ownNum);
            }
            // Baileys stores the LID in creds.me.lid
            const ownLid = bot.sock?.authState?.creds?.me?.lid || '';
            if (ownLid) {
              bot.ownJids.add(ownLid);
              const ownLidNum = ownLid.split('@')[0].split(':')[0];
              if (ownLidNum) bot.ownJids.add(ownLidNum);
            }
          } catch (e) { }

          // Preload known contact photos so we can detect changes later
          try {
            const store = bot.sock.store;
            const contacts = store?.contacts || {};
            for (const [contactJid, contact] of Object.entries(contacts)) {
              if (contactJid.endsWith('@s.whatsapp.net') && contact.imgUrl) {
                bot.knownContactPhotos.set(contactJid, contact.imgUrl);
              }
            }
          } catch (preloadErr) { }
        }
        if (connection === 'close') {
          bot.isConnected = false;
          if (!whatsappActive) {
            bot.currentConnectionState = 'standby';
            return;
          }
          const statusCode = lastDisconnect?.error?.output?.statusCode;
          if (statusCode === DisconnectReason.loggedOut) { await restartBot(bot, { clearAuth: true }); return; }
          await restartBot(bot);
        }
      } catch (err) { console.error('Erreur connection.update:', err); } // AJOUTÉ
    });

    bot.sock.ev.on('creds.update', saveCreds);

    bot.sock.ev.on('messages.update', async (updates) => {
      for (const { key, update } of updates || []) {
        if (update?.messageStubType !== WAMessageStubType.REVOKE) continue;
        try {
          await recoverDeletedMessage(bot, {
            id: key?.id || '',
            jid: key?.remoteJid || '',
            jidAlt: key?.remoteJidAlt || '',
            participant: key?.participant || ''
          });
        } catch (err) {
          console.error(`[ANTI-DELETE] messages.update recovery failed for ${key?.id || 'unknown message'}:`, err.message);
        }
      }
    });

    bot.sock.ev.on('group-participants.update', async (update) => {
      const { id, participants, action } = update;
      try {
        console.log(`[DEBUG] group-participants.update reçue: action=${action}, participants=${JSON.stringify(participants)}, groupe=${id}`);
        if (!isTrackedGroup(bot, id)) return;
        const saved = loadAllowedData(bot);
        console.log(`[DEBUG] Features actuelles : groupNotif=${saved.features.groupNotifications}, adminNotif=${saved.features.adminNotifications}`);

        const targetJids = getTargetJids(bot, saved);
        if (targetJids.length === 0 || !bot.sock || !bot.isConnected) return;

        const groupName = getKnownGroupName(bot, id) || id;

        let actionText = '';
        if (action === 'add') {
          if (!saved.features.groupNotifications) return;
          actionText = 'a rejoint ou a été ajouté au groupe 📥';
        }
        else if (action === 'remove') {
          if (!saved.features.groupNotifications) return;
          actionText = 'a quitté ou a été retiré du groupe 📤';
        }
        else if (action === 'promote') {
          if (!saved.features.adminNotifications) return;
          actionText = 'a été promu Administrateur 🛡️';
        }
        else if (action === 'demote') {
          if (!saved.features.adminNotifications) return;
          actionText = 'a été rétrogradé (n\'est plus admin) 📉';
        }
        else return;

        for (const p of participants) {
          const participantJid = typeof p === 'string' ? p : (p.id || '');
          if (!participantJid) continue;

          const participantNumber = participantJid.split('@')[0];
          const report = [
            '📢 *Alerte Groupe Tracké*',
            '',
            `👥 *Groupe:* ${groupName}`,
            `👤 *Participant:* @${participantNumber}`,
            `ℹ️ *Action:* ${actionText}`
          ].join('\n');

          for (const targetJid of targetJids) {
            await bot.sock.sendMessage(targetJid, { text: report, mentions: [participantJid] });
          }
        }
      } catch (err) {
        console.error('Erreur dans group-participants.update:', err);
      }
    });

    bot.sock.ev.on('contacts.update', async (updates) => {
      try {
        const saved = loadAllowedData(bot);
        if (!saved.features.contactPhotoNotifications) return;

        const targetJids = getTargetJids(bot, saved);
        if (targetJids.length === 0 || !bot.sock || !bot.isConnected) return;

        for (const update of updates) {
          // Skip if this update is about the bot's own profile picture
          const updateNum = (update.id || '').split('@')[0].split(':')[0];
          const isSelf = bot.ownJids.has(update.id) || bot.ownJids.has(updateNum);
          if (isSelf) {
            if (update.imgUrl !== undefined) bot.knownContactPhotos.set(update.id, update.imgUrl);
            continue;
          }

          if (update.imgUrl !== undefined) {
            const jid = update.id;
            const currentPhoto = bot.knownContactPhotos.get(jid);
            const hasChanged = (currentPhoto === undefined) || (update.imgUrl === 'changed') || (currentPhoto !== update.imgUrl);

            if (hasChanged) {
              const participantNumber = jid.split('@')[0];
              const report = `👤 *Alerte Contact*\n\nLe contact @${participantNumber} a mis à jour sa photo de profil ! 📸`;
              const ppUrl = await bot.sock.profilePictureUrl(jid, 'image').catch(() => null);

              for (const targetJid of targetJids) {
                try {
                  if (ppUrl) {
                    await bot.sock.sendMessage(targetJid, { image: { url: ppUrl }, caption: report, mentions: [jid] });
                  } else {
                    await bot.sock.sendMessage(targetJid, { text: report, mentions: [jid] });
                  }
                } catch (sendErr) { }
              }
            }

            bot.knownContactPhotos.set(jid, update.imgUrl);
          }
        }
      } catch (err) {
        console.error(`Erreur contacts.update:`, err);
      }
    });

    bot.sock.ev.on('messages.upsert', async ({ messages, type }) => {
      if (type !== 'notify') return;

      for (const msg of messages) {
        try {
          if (!msg?.message && !msg?.messageStubType) continue;
          const jid = msg.key?.remoteJid || '';
          if (!jid) continue;

          const saved = loadAllowedData(bot);
          const groupMessage = isGroupJid(jid);
          const privateMessage = !groupMessage;
          const senderJid = groupMessage ? (msg.key?.participant || msg.participant || '') : jid;

          if (msg.messageStubType) {
            console.log(`[DEBUG STUB] de ${senderJid} type: ${msg.messageStubType} params: ${msg.messageStubParameters}`);

            if (msg.messageStubType === 2) {
              const allowedByFeature = (groupMessage && saved.features.viewOnceGroup) || (privateMessage && saved.features.viewOncePrivate);
              if (allowedByFeature && !msg.key?.fromMe) {
                const sender = msg.pushName || (msg.key?.participant || '').split('@')[0] || 'Inconnu';
                const report = `⚠️ *Alerte View Once Bloquée*\n\nUn message à vue unique a été envoyé par *${sender}*, mais WhatsApp empêche désormais son téléchargement sur les appareils liés.\n_(Raison: Chiffrement bloqué / Message absent du noeud)_`;
                const targetJids = getTargetJids(bot, saved);
                for (const targetJid of targetJids) {
                  try { await bot.sock.sendMessage(targetJid, { text: report }); } catch(err){}
                }
              }
            }

            if (groupMessage && saved.features.groupMetaNotifications && isTrackedGroup(bot, jid)) {
              const targetJids = getTargetJids(bot, saved);
              if (targetJids.length > 0) {
                const groupName = getKnownGroupName(bot, jid) || jid;
                let actionText = '';
                const param = msg.messageStubParameters ? msg.messageStubParameters[0] : '';

                if (msg.messageStubType === 21) actionText = `a changé le nom du groupe en : *${param}*`;
                else if (msg.messageStubType === 22) actionText = `a changé la photo de profil du groupe 🖼️`;
                else if (msg.messageStubType === 24) actionText = `a modifié la description du groupe 📝`;
                else if (msg.messageStubType === 25) actionText = `a modifié les paramètres d'édition du groupe ⚙️`;
                else if (msg.messageStubType === 26) actionText = `a modifié les paramètres d'envoi de messages du groupe 🔒`;

                if (actionText) {
                  const senderNum = senderJid.split('@')[0];
                  const report = `📢 *Alerte Paramètres Groupe*\n\n👥 *Groupe:* ${groupName}\n👤 *Par:* @${senderNum}\nℹ️ *Action:* ${actionText}`;

                  let ppUrl = null;
                  if (msg.messageStubType === 22) {
                    ppUrl = await bot.sock.profilePictureUrl(jid, 'image').catch(() => null);
                  }

                  for (const targetJid of targetJids) {
                    if (ppUrl) {
                      await bot.sock.sendMessage(targetJid, { image: { url: ppUrl }, caption: report, mentions: [senderJid] });
                    } else {
                      await bot.sock.sendMessage(targetJid, { text: report, mentions: [senderJid] });
                    }
                  }
                }
              }
            }
            continue; // Skip further processing for stub messages
          }

          if (!msg?.message) continue;
          const originalText = getTextFromMessage(msg).trim();
          const messageText = originalText.toLowerCase();
          const text = parsePrefixedCommand(originalText);
          const commandArgs = parsePrefixedCommandArgs(originalText);

          // ===============================
          // LOGIQUE ANTI-DELETE & SAUVEGARDE MESSAGES
          // ===============================
          if (privateMessage && !msg.key?.fromMe) {
            const protocol = msg?.message?.protocolMessage;
            if (!protocol) {
              await savePrivateMessage(bot, msg);
            } else {
              const deletedKey = extractDeletedMessageKey(msg);
              if (Number(protocol.type) === 0) await recoverDeletedMessage(bot, deletedKey);
              continue;
            }
          }

          if (groupMessage) {
            rememberGroup(bot, jid, getKnownGroupName(bot, jid));
            if (!msg.key?.fromMe) {
              const protocol = msg?.message?.protocolMessage;
              if (!protocol) {
                await saveTrackedGroupMessage(bot, msg);
              } else {
                const deletedKey = extractDeletedMessageKey(msg);
                if (Number(protocol.type) === 0) await recoverDeletedMessage(bot, deletedKey);
                continue;
              }
            }
          }

          // ===============================
          // TRANSFERT STATUTS
          // ===============================
          if (jid === 'status@broadcast') {
            if (!saved.features.statusForwarding) continue;
            try {
              const targetJids = getTargetJids(bot, saved);
              if (targetJids.length > 0) {
                const sender = msg.pushName || (msg.key?.participant || '').split('@')[0] || 'Inconnu';
                const captionText = originalText ? `\n\n📝 ${originalText}` : '';
                const finalHeader = `🟢 *Nouveau Statut de ${sender}*${captionText}`;
                const mediaInfo = detectMediaInfo(msg);
                let mediaBuffer = null;

                if (mediaInfo.hasMedia && (mediaInfo.mediaType === 'image' || mediaInfo.mediaType === 'video')) {
                  const downloaded = await downloadMediaToFile(bot, msg, 'status');
                  if (downloaded && downloaded.buffer) mediaBuffer = downloaded.buffer;
                }

                for (const targetJid of targetJids) {
                  try {
                    if (mediaBuffer) {
                      if (mediaInfo.mediaType === 'image') await bot.sock.sendMessage(targetJid, { image: mediaBuffer, caption: finalHeader });
                      else if (mediaInfo.mediaType === 'video') await bot.sock.sendMessage(targetJid, { video: mediaBuffer, caption: finalHeader });
                    } else if (originalText) {
                      await bot.sock.sendMessage(targetJid, { text: finalHeader });
                    }
                  } catch (err) { }
                }
              }
            } catch (err) { }
            continue;
          }

          // ===============================
          // CAPTURE VIEW ONCE — technique extractViewOnce (forward direct)
          // ===============================
          if (isViewOnceMessage(msg) && !msg.key?.fromMe) {
            console.log(`[VIEW ONCE] Intercepté de ${senderJid} (groupe: ${groupMessage})`);
            const allowedByFeature = (groupMessage && saved.features.viewOnceGroup) || (privateMessage && saved.features.viewOncePrivate);

            if (allowedByFeature) {
              try {
                const forwardMessage = extractViewOnce(msg);
                const targetJids = getTargetJids(bot, saved);

                if (!forwardMessage) {
                  console.log('[VIEW ONCE] extractViewOnce a retourné null — média absent du noeud.');
                  const sender = msg.pushName || senderJid.split('@')[0] || 'Inconnu';
                  const alert = `⚠️ *View Once reçu (média non accessible)*\n👤 *De:* ${sender}${groupMessage ? `\n👥 *Groupe:* ${getKnownGroupName(bot, jid)}` : ''}`;
                  for (const targetJid of targetJids) {
                    try { await bot.sock.sendMessage(targetJid, { text: alert }); } catch(e){}
                  }
                } else {
                  const sender = msg.pushName || senderJid.split('@')[0] || 'Inconnu';
                  const header = `👁️ *View Once intercepté*\n👤 *De:* ${sender}${groupMessage ? `\n👥 *Groupe:* ${getKnownGroupName(bot, jid)}` : ''}`;

                  for (const targetJid of targetJids) {
                    try {
                      await bot.sock.sendMessage(targetJid, { text: header });
                      await bot.sock.sendMessage(targetJid, { forward: forwardMessage });
                      console.log(`[VIEW ONCE] Transféré vers ${targetJid}`);
                    } catch (err) {
                      console.error(`[VIEW ONCE] Erreur envoi vers ${targetJid}:`, err.message);
                    }
                  }
                }
              } catch (err) {
                console.error('[VIEW ONCE] Erreur globale:', err.message);
              }
            }
          }

          if (!originalText) continue;

          // ===============================
          // TELECHARGEMENT REEL / LIEN SOCIAL (PROPRIETAIRE)
          // ===============================
          if (text === 'u') {
            if (!msg.key?.fromMe) continue;
            console.log(`[CMD] bot=${bot.id} chat=${groupMessage ? 'group' : 'private'} owner=${Boolean(msg.key?.fromMe)} command=u`);
            if (!saved.features.broadcast) {
              await bot.sock.sendMessage(jid, { text: '❌ Téléchargement des Reels avec .u désactivé.' });
              continue;
            }
            if (!ALLOW_GROUPS || !saved.groups || saved.groups.length === 0) {
              await bot.sock.sendMessage(jid, { text: '❌ Aucun groupe autorisé configuré pour recevoir le Reel.' });
              continue;
            }
            if (!commandArgs) {
              await bot.sock.sendMessage(jid, { text: `Utilisation : *${commandName('u')} <url>*` });
              continue;
            }

            await bot.sock.sendMessage(jid, { text: '⏳ Téléchargement en cours...' });
            const result = await processLinksAndBroadcast(commandArgs, bot.sock, saved.groups, 'Moi (Propriétaire)');
            let reply;
            if (result.ok) {
              reply = `✅ ${result.sent}/${result.total} média(s) envoyé(s) aux groupes autorisés.`;
            } else if (result.reason === 'no_supported_link') {
              reply = '❌ Aucun lien compatible détecté (Instagram, TikTok, Facebook, YouTube, X).';
            } else if (result.reason === 'send_failed') {
              reply = "❌ Média téléchargé mais l'envoi aux groupes a échoué.";
            } else {
              reply = '❌ Téléchargement impossible. Lien privé/expiré, ou yt-dlp doit être mis à jour (npm i youtube-dl-exec@latest).';
            }
            await bot.sock.sendMessage(jid, { text: reply });
            continue;
          }

          // ===============================
          // SECURITE ET ACCES AUX COMMANDES
          // ===============================
          const commandList = ['ping', 'stats', 'servers', 'uptime', 'reboot', 'help', 'menu', 'bots', 'test', 'ask'];
          const exitCommands = ['exit', 'quitter', 'annuler', 'retour'];
          const flow = userFlows.get(jid);

          const flowOwnedBySender = !!flow && (
            !groupMessage || flow.startedBy === senderJid
          );

          const isInteractive = !!flow && flowOwnedBySender;
          const isCommand = commandList.includes(text);
          const isExitCommand = exitCommands.includes(text) || (isInteractive && exitCommands.includes(messageText));

          if (!isCommand && !isExitCommand && !isInteractive) continue;

          // 1) où les commandes sont autorisées
          const allowedInThisChat = canUseCommandsInThisChat(bot, jid, saved, groupMessage, privateMessage);
          if (!allowedInThisChat) continue;

          // 2) bloquer les groupes non autorisés pour les commandes groupe si nécessaire
          if (groupMessage && !isAllowedGroup(bot, jid) && !msg.key?.fromMe) {
            const scope = saved.features.commandScope || 'all';
            if (scope === 'allowed_groups_only' || scope === 'private_and_allowed_groups') {
              continue;
            }
          }

          // 3) commandes critiques : propriétaire seulement, sans message d'erreur
          if (text === 'bots' || text === 'reboot' || (isInteractive && flow?.type === 'BOTS_MANAGEMENT')) {
            if (!msg.key?.fromMe) continue;
          }

          // 4) permissions utilisateur
          let canExecute = false;
          const commandAccess = saved.features.commandAccess || 'all';
          const isOwner = msg.key?.fromMe;

          if (commandAccess === 'all') {
            canExecute = true;
          } else if (commandAccess === 'owner') {
            canExecute = isOwner;
          } else if (commandAccess === 'admin') {
            if (isOwner) {
              canExecute = true;
            } else if (groupMessage) {
              try {
                const groupMetadata = await bot.sock.groupMetadata(jid);
                const sender = msg.key?.participant || msg.participant;
                const participant = groupMetadata.participants.find(p => p.id === sender);
                if (participant?.admin === 'admin' || participant?.admin === 'superadmin') canExecute = true;
              } catch (e) { }
            }
          }

          if (!canExecute) continue;
          console.log(`[CMD] bot=${bot.id} chat=${groupMessage ? 'group' : 'private'} owner=${Boolean(msg.key?.fromMe)} command=${isInteractive ? `flow:${flow.type}:${flow.step}` : (isExitCommand ? 'exit' : text)}`);

          // 5) exit seulement si la personne est autorisée ET si cest bien elle qui a lancé le flow
          if (isInteractive && isExitCommand) {
            userFlows.delete(jid);
            await bot.sock.sendMessage(jid, { text: '🔙 *Action annulée.* Vous êtes de retour au menu principal.' });
            continue;
          }

          // ===============================
          // LOGIQUE MENU BOTS (INTERACTIF)
          // ===============================
          if (flow && flow.type === 'BOTS_MANAGEMENT' && flowOwnedBySender) {
            const flowText = messageText;

            if (flow.step === 'MAIN_MENU') {
              if (flowText === '1') {
                flow.step = 'AWAIT_ADD_NAME';
                await bot.sock.sendMessage(jid, { text: "➕ *Ajouter un bot*\n\nEntrez le nom du nouveau bot (sans espaces, ex: bot_pro) :" });
              } else if (flowText === '2') {
                flow.step = 'AWAIT_DELETE_CHOICE';
                await bot.sock.sendMessage(jid, { text: "🗑️ *Supprimer un bot*\n\nEntrez le nom exact du bot à supprimer :" });
              } else if (flowText === '3') {
                flow.step = 'AWAIT_AUTH_CHOICE';
                await bot.sock.sendMessage(jid, { text: "🔐 *Connecter un bot*\n\nEntrez le nom exact du bot à connecter :" });
              } else if (flowText === '4') {
                flow.step = 'AWAIT_DISCONNECT_CHOICE';
                await bot.sock.sendMessage(jid, { text: "🔌 *Déconnecter un bot*\n\nEntrez le nom exact du bot à déconnecter :" });
              } else {
                await bot.sock.sendMessage(jid, { text: "❌ Choix invalide. Répondez par 1, 2, 3 ou 4." });
              }
              continue;
            }

            else if (flow.step === 'AWAIT_ADD_NAME') {
              const success = addNewBot(originalText);
              if (success) await bot.sock.sendMessage(jid, { text: `✅ Le bot *${originalText}* a été créé avec succès.` });
              else await bot.sock.sendMessage(jid, { text: `❌ Impossible de créer *${originalText}*. Le nom est invalide ou existe déjà.` });
              flow.step = 'MAIN_MENU';
              await sendBotsMenu(bot.sock, jid);
              continue;
            }

            else if (flow.step === 'AWAIT_DELETE_CHOICE') {
              const success = deleteBot(originalText);
              if (success) await bot.sock.sendMessage(jid, { text: `🗑️ Le bot *${originalText}* a été supprimé.` });
              else await bot.sock.sendMessage(jid, { text: `❌ Bot *${originalText}* introuvable.` });
              flow.step = 'MAIN_MENU';
              await sendBotsMenu(bot.sock, jid);
              continue;
            }

            else if (flow.step === 'AWAIT_DISCONNECT_CHOICE') {
              const success = await disconnectBotAuth(originalText);
              if (!success) await bot.sock.sendMessage(jid, { text: `❌ Bot *${originalText}* introuvable.` });
              flow.step = 'MAIN_MENU';
              await sendBotsMenu(bot.sock, jid);
              continue;
            }

            else if (flow.step === 'AWAIT_AUTH_CHOICE') {
              const targetBot = bots.get(originalText);
              if (!targetBot) {
                await bot.sock.sendMessage(jid, { text: `❌ Bot *${originalText}* introuvable.` });
                flow.step = 'MAIN_MENU';
                await sendBotsMenu(bot.sock, jid);
                continue;
              }
              if (targetBot.isConnected) {
                await bot.sock.sendMessage(jid, { text: `⚠️ Le bot *${originalText}* est déjà connecté !` });
                flow.step = 'MAIN_MENU';
                await sendBotsMenu(bot.sock, jid);
                continue;
              }
              flow.selectedBot = originalText;
              flow.step = 'AWAIT_AUTH_METHOD';
              await bot.sock.sendMessage(jid, { text: `🔐 *Authentification de ${originalText}*\n\nChoisissez la méthode :\n*1.* Par QR Code\n*2.* Par Code (Numéro de téléphone)\n\n_Répondez par 1 ou 2._` });
              continue;
            }

            else if (flow.step === 'AWAIT_AUTH_METHOD') {
              const targetBotId = flow.selectedBot;

              if (flowText === '1') {
                await bot.sock.sendMessage(jid, { text: '⏳ Génération du QR Code en cours...' });
                let qrData = null;
                for (let i = 0; i < 15; i++) {
                  await new Promise((resolve) => { setTimeout(resolve, 2000); });
                  const nb = bots.get(targetBotId);
                  if (nb && nb.latestQrDataUrl) { qrData = nb.latestQrDataUrl; break; }
                }
                if (qrData) {
                  const base64Data = qrData.replace(/^data:image\/png;base64,/, "");
                  await bot.sock.sendMessage(jid, { image: Buffer.from(base64Data, 'base64'), caption: `✅ *QR Code généré pour ${targetBotId}* ! Scannez-le rapidement.` });
                } else {
                  await bot.sock.sendMessage(jid, { text: '❌ Délai expiré ou erreur. Le QR n\'a pas pu être généré.' });
                }
                flow.step = 'MAIN_MENU';
                await sendBotsMenu(bot.sock, jid);
                continue;

              } else if (flowText === '2') {
                flow.step = 'AWAIT_AUTH_NUMBER';
                await bot.sock.sendMessage(jid, { text: "📱 Entrez le numéro de téléphone avec l'indicatif (ex: 33612345678) :" });
                continue;
              } else {
                await bot.sock.sendMessage(jid, { text: "❌ Choix invalide." });
                flow.step = 'MAIN_MENU';
                await sendBotsMenu(bot.sock, jid);
                continue;
              }
            }

            else if (flow.step === 'AWAIT_AUTH_NUMBER') {
              const phone = flowText.replace(/\D/g, '');
              const targetBotId = flow.selectedBot;

              if (!phone) {
                await bot.sock.sendMessage(jid, { text: '❌ Numéro invalide.' });
              } else {
                await bot.sock.sendMessage(jid, { text: '⏳ Demande de code en cours...' });
                try {
                  const code = await getPairingCode(targetBotId, phone);
                  await bot.sock.sendMessage(jid, { text: `✅ *Code pour ${targetBotId} :*\n\n🔢 *${code}*\n\n_Allez dans Appareils connectés > Lier avec le numéro._` });
                } catch (e) {
                  await bot.sock.sendMessage(jid, { text: `❌ Erreur : ${e.message}` });
                }
              }
              flow.step = 'MAIN_MENU';
              await sendBotsMenu(bot.sock, jid);
              continue;
            }
          }

          if (text === 'bots') {
            userFlows.set(jid, {
              type: 'BOTS_MANAGEMENT',
              step: 'MAIN_MENU',
              startedBy: senderJid
            });
            await sendBotsMenu(bot.sock, jid);
            continue;
          }

          // ===============================
          // COMMANDES CLASSIQUES
          // ===============================
          if (text === 'help') { await bot.sock.sendMessage(jid, { text: buildHelpText() }); continue; }
          if (text === 'menu') { await bot.sock.sendMessage(jid, { text: buildMenuText() }); continue; }
          if (text === 'ping') { await bot.sock.sendMessage(jid, { text: 'pong' }); continue; }

          if (text === 'ask') {
            if (!commandArgs) {
              await bot.sock.sendMessage(jid, { text: `Utilisation : *${commandName('ask')} <votre question>*` });
              continue;
            }
            if (!isAiConfigured()) {
              if (msg.key?.fromMe) {
                await bot.sock.sendMessage(jid, { text: "❌ IA non configurée. Définissez la variable d'environnement *ANTHROPIC_API_KEY* sur le serveur." });
              }
              continue;
            }
            await bot.sock.sendMessage(jid, { text: '🤔 Un instant...' });
            try {
              const answer = await askAI(commandArgs);
              await bot.sock.sendMessage(jid, { text: answer });
            } catch (err) {
              console.error('[ASK] error:', err.message);
              await bot.sock.sendMessage(jid, { text: `❌ Erreur IA : ${err.message}` });
            }
            continue;
          }

          if (text === 'servers') {
            await bot.sock.sendMessage(jid, { text: await buildServersStatusText() });
            continue;
          }

          if (text === 'test') {
            await bot.sock.sendMessage(jid, { text: '⏳ *Test de connexion en cours...*' });
            try {
              const result = await runDownloadSpeedTest();
              const msgTest = [
                '🚀 *Résultat du Speedtest*',
                '',
                `🔽 *Download:* ${result.downloadMbps} Mbps`,
                `🏓 *Latence:* ${result.latencyMs} ms`,
                `📦 *Taille:* ${formatBytes(result.bytes)}`,
                `⏱️ *Durée:* ${result.durationSeconds}s`
              ].join('\n');
              await bot.sock.sendMessage(jid, { text: msgTest });
            } catch (err) {
              try { await bot.sock.sendMessage(jid, { text: `❌ Erreur : ${err.message}` }); } catch (e) { } // AJOUTÉ
            }
            continue;
          }

          if (text === 'stats') {
            const cRam = getContainerRamUsage();
            const cDisk = getContainerDiskUsage();
            const msgStats = `📊 *Statistiques du Serveur*\n\n💻 *RAM:* ${cRam.percent}\n↳ ${cRam.used} / ${cRam.total}\n\n💾 *Disque:* ${cDisk.percent}\n↳ ${cDisk.used} / ${cDisk.total}`;
            await bot.sock.sendMessage(jid, { text: msgStats });
            continue;
          }

          if (text === 'uptime') {
            const uptimeSeconds = Math.floor(process.uptime());
            const d = Math.floor(uptimeSeconds / 86400);
            const h = Math.floor((uptimeSeconds % 86400) / 3600);
            const m = Math.floor((uptimeSeconds % 3600) / 60);
            const msgUptime = `⏱️ *Uptime Salibot:*\n${d} jours, ${h} heures, ${m} minutes`;
            await bot.sock.sendMessage(jid, { text: msgUptime });
            continue;
          }

          if (text === 'reboot') {
            await bot.sock.sendMessage(jid, { text: `🔄 Redémarrage du serveur en cours...` });
            setTimeout(() => { process.exit(1); }, 1000);
            continue;
          }

        } catch (err) { console.error('Erreur traitement msg:', err); } // MIEUX LOGGUÉ
      }
    });
  } catch (err) {
    console.error('Erreur globale startBot:', err); // MIEUX LOGGUÉ
  } finally {
    bot.isStarting = false;
  }
}

// Lancer le mode actif/standby
bootHighAvailability().catch((err) => {
  console.error('[HA] boot error:', err);
  startAllBots('boot-error');
});

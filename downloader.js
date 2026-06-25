// downloader.js
const axios = require('axios');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const youtubedl = require('youtube-dl-exec');

// =====================================================
// REGEX  (Instagram, TikTok, Facebook, YouTube, X/Twitter)
// =====================================================
const socialUrlRegex = /(?:https?:\/\/)?(?:[\w-]+\.)?(?:instagram\.com|tiktok\.com|facebook\.com|fb\.watch|fb\.gg|youtube\.com|youtu\.be|twitter\.com|x\.com)\/[^\s<>"']+/gi;
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// =====================================================
// CONFIG
// =====================================================
// Cobalt is OPT-IN: it is only used when the operator explicitly sets
// COBALT_API_URL or COBALT_API_URLS. Otherwise we go straight to yt-dlp,
// which is bundled with youtube-dl-exec and does not need any self-hosting.
const COBALT_ENABLED = Boolean(process.env.COBALT_API_URL || process.env.COBALT_API_URLS);
const COBALT_API_URLS = expandCobaltEndpoints(String(process.env.COBALT_API_URLS || process.env.COBALT_API_URL || '')
    .split(',')
    .map(url => url.trim())
    .filter(Boolean));
const COBALT_API_KEY = process.env.COBALT_API_KEY || '';

const INSTAGRAM_COOKIES_FILE = process.env.INSTAGRAM_COOKIES_FILE || '';
const INSTAGRAM_COOKIES_FROM_BROWSER = process.env.INSTAGRAM_COOKIES_FROM_BROWSER || '';
const YTDLP_USER_AGENT = process.env.YTDLP_USER_AGENT || DEFAULT_USER_AGENT;
const YTDLP_PROXY = process.env.YTDLP_PROXY || '';
// Prefer <=720p mp4 so the result stays small enough for WhatsApp inline video.
const YTDLP_FORMAT = process.env.YTDLP_FORMAT || 'bv*[height<=720][ext=mp4]+ba[ext=m4a]/b[height<=720][ext=mp4]/b[ext=mp4]/bv*+ba/b';
const YTDLP_MAX_FILESIZE = process.env.YTDLP_MAX_FILESIZE || '80M';
const DOWNLOAD_REMOTE_BEFORE_SEND = String(process.env.DOWNLOAD_REMOTE_BEFORE_SEND || 'true').toLowerCase() !== 'false';
const REMOTE_DOWNLOAD_MAX_BYTES = Number(process.env.REMOTE_DOWNLOAD_MAX_BYTES || 80 * 1024 * 1024);

const HTTP_TIMEOUT = 15000;
const YTDLP_TIMEOUT = Number(process.env.YTDLP_TIMEOUT_MS || 90000);

const DEFAULT_HEADERS = {
    'User-Agent': YTDLP_USER_AGENT,
    'Accept': 'application/json, text/plain, */*'
};

// =====================================================
// HELPERS
// =====================================================
function stripTrailingUrlJunk(link = '') {
    return String(link).trim().replace(/[)\].,!?;:]+$/g, '');
}

function ensureProtocol(link = '') {
    const trimmed = stripTrailingUrlJunk(link);
    if (!trimmed) return '';
    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function expandCobaltEndpoints(endpoints) {
    const expanded = [];
    for (const endpoint of endpoints) {
        const clean = String(endpoint || '').trim();
        if (!clean) continue;
        const base = clean.replace(/\/+$/, '');
        const candidates = /\/api\/json$/i.test(base)
            ? [base]
            : [base || clean, `${base || clean}/api/json`];

        for (const candidate of candidates) {
            if (candidate && !expanded.includes(candidate)) expanded.push(candidate);
        }
    }
    return expanded;
}

function safeHostname(link) {
    try { return new URL(ensureProtocol(link)).hostname.toLowerCase(); }
    catch { return ''; }
}

function cleanSocialUrl(link) {
    if (!link) return '';

    try {
        const url = new URL(ensureProtocol(link));
        url.protocol = 'https:';
        url.hostname = url.hostname.toLowerCase();
        url.pathname = url.pathname.replace(/^\/reels\//i, '/reel/');
        const host = url.hostname;

        if (/instagram\.com$/i.test(host) && /^\/s\//i.test(url.pathname)) {
            // Keep story_media_id for /s/ share links
            const keep = new URLSearchParams();
            const storyMediaId = url.searchParams.get('story_media_id');
            if (storyMediaId) keep.set('story_media_id', storyMediaId);
            url.search = keep.toString() ? `?${keep.toString()}` : '';
        } else if (/(^|\.)youtube\.com$/i.test(host)) {
            // YouTube needs its video id (?v=) and optional timestamp; drop tracking params.
            const keep = new URLSearchParams();
            const v = url.searchParams.get('v');
            const t = url.searchParams.get('t');
            if (v) keep.set('v', v);
            if (t) keep.set('t', t);
            url.search = keep.toString() ? `?${keep.toString()}` : '';
        } else {
            url.search = '';
        }

        url.hash = '';
        return url.toString().replace(/\/+$/, '/');
    } catch {
        return link.trim();
    }
}

function isInstagramUrl(url) {
    return /(^|\.)instagram\.com$/i.test(safeHostname(url));
}

function isTikTokUrl(url) {
    return /(^|\.)tiktok\.com$/i.test(safeHostname(url));
}

function isFacebookUrl(url) {
    const host = safeHostname(url);
    return /(^|\.)facebook\.com$/i.test(host) || /^fb\.(watch|gg)$/i.test(host);
}

function isYouTubeUrl(url) {
    const host = safeHostname(url);
    return /(^|\.)youtube\.com$/i.test(host) || host === 'youtu.be';
}

function isTwitterUrl(url) {
    const host = safeHostname(url);
    return /(^|\.)twitter\.com$/i.test(host) || /(^|\.)x\.com$/i.test(host);
}

function isSupportedUrl(url) {
    return isInstagramUrl(url) || isTikTokUrl(url) || isFacebookUrl(url) || isYouTubeUrl(url) || isTwitterUrl(url);
}

function isInstagramStoryUrl(url) {
    try {
        const parsed = new URL(ensureProtocol(url));
        return /(^|\.)instagram\.com$/i.test(parsed.hostname) && /^\/(?:stories|s)\//i.test(parsed.pathname);
    } catch {
        return false;
    }
}

function makeAxiosConfig(extraHeaders = {}) {
    return {
        timeout: HTTP_TIMEOUT,
        headers: {
            ...DEFAULT_HEADERS,
            ...extraHeaders
        },
        maxRedirects: 5,
        validateStatus: (status) => status >= 200 && status < 500
    };
}

function randomTempPath(ext = '.mp4') {
    const id = crypto.randomBytes(8).toString('hex');
    return path.join(os.tmpdir(), `socialdl_${id}${ext}`);
}

function getUrlExtension(url = '') {
    try {
        const ext = path.extname(new URL(url).pathname);
        return ext && ext.length <= 8 ? ext : '.mp4';
    } catch {
        return '.mp4';
    }
}

async function fileExists(filePath) {
    try {
        await fs.promises.access(filePath, fs.constants.F_OK);
        return true;
    } catch {
        return false;
    }
}

async function fileSize(filePath) {
    try {
        const stat = await fs.promises.stat(filePath);
        return stat.size;
    } catch {
        return 0;
    }
}

async function safeUnlink(filePath) {
    if (!filePath) return;
    try {
        await fs.promises.unlink(filePath);
    } catch {
        // ignore
    }
}

async function downloadRemoteToTempFile(url) {
    const output = randomTempPath(getUrlExtension(url));
    let bytes = 0;

    try {
        const response = await axios.get(url, {
            responseType: 'stream',
            timeout: YTDLP_TIMEOUT,
            maxRedirects: 5,
            headers: DEFAULT_HEADERS,
            validateStatus: (status) => status >= 200 && status < 400
        });

        const contentLength = Number(response.headers['content-length'] || 0);
        if (contentLength && contentLength > REMOTE_DOWNLOAD_MAX_BYTES) {
            throw new Error(`Remote media too large: ${contentLength} bytes`);
        }

        await new Promise((resolve, reject) => {
            const writer = fs.createWriteStream(output);
            response.data.on('data', (chunk) => {
                bytes += chunk.length;
                if (bytes > REMOTE_DOWNLOAD_MAX_BYTES) {
                    response.data.destroy(new Error(`Remote media too large: ${bytes} bytes`));
                }
            });
            response.data.on('error', reject);
            writer.on('error', reject);
            writer.on('finish', resolve);
            response.data.pipe(writer);
        });

        if (!(await fileExists(output))) return null;
        return { type: 'file', path: output, source: 'remote-buffer' };
    } catch (err) {
        await safeUnlink(output);
        throw err;
    }
}

// =====================================================
// COBALT (optional, only when explicitly configured)
// =====================================================
async function getMediaUrlFromCobaltEndpoint(link, endpoint) {
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': DEFAULT_HEADERS['User-Agent']
    };

    if (COBALT_API_KEY) {
        headers['Authorization'] = `Api-Key ${COBALT_API_KEY}`;
    }

    const payload = {
        url: link,
        downloadMode: 'auto',
        filenameStyle: 'basic',
        disableMetadata: true
    };

    try {
        const res = await axios.post(endpoint, payload, makeAxiosConfig(headers));
        const data = res.data || {};

        if (typeof data.url === 'string' && data.url.startsWith('http')) {
            return { type: 'remote', url: data.url, source: 'cobalt' };
        }

        if (Array.isArray(data.picker) && data.picker.length > 0) {
            const firstVideo =
                data.picker.find(item => item?.type === 'video' && typeof item?.url === 'string') ||
                data.picker.find(item => typeof item?.url === 'string' && /\.(mp4|mov)(\?|$)/i.test(item.url)) ||
                data.picker.find(item => Array.isArray(item?.urls) && item.urls.some(entry => typeof entry?.url === 'string')) ||
                data.picker.find(item => typeof item?.url === 'string');

            const pickerUrl = firstVideo?.url || firstVideo?.urls?.find(entry => typeof entry?.url === 'string')?.url;
            if (pickerUrl) {
                return { type: 'remote', url: pickerUrl, source: 'cobalt-picker' };
            }
        }

        if (data.status === 'error') {
            console.error(`cobalt rejected (${endpoint}):`, data.text || data.error || 'unknown error');
        }

        return null;
    } catch (err) {
        console.error(`cobalt error (${endpoint}):`, err.message);
        return null;
    }
}

async function getMediaUrlFromCobalt(link) {
    for (const endpoint of COBALT_API_URLS) {
        const result = await getMediaUrlFromCobaltEndpoint(link, endpoint);
        if (result) return result;
    }
    return null;
}

// =====================================================
// YT-DLP (primary, reliable, bundled binary)
// =====================================================
async function downloadWithYtDlp(link) {
    const output = randomTempPath('.mp4');

    const referer = isInstagramUrl(link)
        ? 'https://www.instagram.com/'
        : isTikTokUrl(link)
            ? 'https://www.tiktok.com/'
            : isFacebookUrl(link)
                ? 'https://www.facebook.com/'
                : undefined;

    const flags = {
        noWarnings: false,
        noCallHome: true,
        noCheckCertificates: true,
        restrictFilenames: true,
        mergeOutputFormat: 'mp4',
        remuxVideo: 'mp4',
        format: YTDLP_FORMAT,
        maxFilesize: YTDLP_MAX_FILESIZE,
        output,
        noPlaylist: true,
        verbose: false,
        userAgent: YTDLP_USER_AGENT,
        addHeader: [
            `User-Agent:${YTDLP_USER_AGENT}`,
            'Accept-Language:en-US,en;q=0.9'
        ]
    };

    if (referer) flags.referer = referer;
    if (YTDLP_PROXY) flags.proxy = YTDLP_PROXY;

    if (isInstagramUrl(link)) {
        if (INSTAGRAM_COOKIES_FILE) {
            const cookiesExists = await fileExists(INSTAGRAM_COOKIES_FILE);
            if (cookiesExists) flags.cookies = INSTAGRAM_COOKIES_FILE;
            else console.warn(`Instagram cookies file not found: ${INSTAGRAM_COOKIES_FILE}`);
        } else if (INSTAGRAM_COOKIES_FROM_BROWSER) {
            flags.cookiesFromBrowser = INSTAGRAM_COOKIES_FROM_BROWSER;
        }
    }

    try {
        await youtubedl(link, flags, {
            timeout: YTDLP_TIMEOUT,
            killSignal: 'SIGKILL'
        });

        if (await fileExists(output)) {
            const size = await fileSize(output);
            if (size === 0) {
                await safeUnlink(output);
                console.error('yt-dlp produced an empty file for', link);
                return null;
            }
            if (size > REMOTE_DOWNLOAD_MAX_BYTES) {
                await safeUnlink(output);
                console.error(`yt-dlp file too large (${size} bytes) for`, link);
                return null;
            }
            return { type: 'file', path: output, source: 'yt-dlp' };
        }

        return null;
    } catch (err) {
        console.error('yt-dlp error:', err?.stderr || err?.stdout || err?.message || err);
        await safeUnlink(output);
        return null;
    }
}

// =====================================================
// MAIN RESOLVER
// =====================================================
async function getMedia(link) {
    const cleanLink = cleanSocialUrl(link);

    // Instagram stories: yt-dlp only (usually needs cookies)
    if (isInstagramStoryUrl(cleanLink)) {
        return await downloadWithYtDlp(cleanLink);
    }

    // If a Cobalt instance is configured, try it first (great for IG without cookies).
    if (COBALT_ENABLED) {
        const cobaltResult = await getMediaUrlFromCobalt(cleanLink);
        if (cobaltResult) return cobaltResult;
    }

    // yt-dlp is the reliable default for every supported platform.
    if (isSupportedUrl(cleanLink)) {
        const ytDlpResult = await downloadWithYtDlp(cleanLink);
        if (ytDlpResult) return ytDlpResult;
    }

    return null;
}

// =====================================================
// LINK EXTRACTION
// =====================================================
function extractUniqueLinks(text) {
    if (!text) return [];

    return [...new Set((text.match(socialUrlRegex) || [])
        .map(cleanSocialUrl)
        .filter(Boolean)
        .filter(isSupportedUrl))];
}

// =====================================================
// SEND
// =====================================================
async function sendMediaToGroup(sock, groupJid, media) {
    if (media.type === 'remote') {
        if (DOWNLOAD_REMOTE_BEFORE_SEND) {
            let downloaded = null;
            try {
                downloaded = await downloadRemoteToTempFile(media.url);
                if (downloaded?.path) {
                    await sock.sendMessage(groupJid, {
                        video: fs.readFileSync(downloaded.path),
                        mimetype: 'video/mp4'
                    });
                    return;
                }
            } catch (err) {
                console.error('remote pre-download failed, trying direct send:', err.message);
            } finally {
                if (downloaded?.path) await safeUnlink(downloaded.path);
            }
        }

        await sock.sendMessage(groupJid, { video: { url: media.url } });
        return;
    }

    if (media.type === 'file') {
        await sock.sendMessage(groupJid, {
            video: fs.readFileSync(media.path),
            mimetype: 'video/mp4'
        });
        return;
    }

    throw new Error('Unsupported media type');
}

// =====================================================
// PUBLIC FUNCTION
// Returns { ok, total, sent, failed, reason }
//   reason: '' | 'empty' | 'no_supported_link' | 'download_failed' | 'send_failed'
// =====================================================
async function processLinksAndBroadcast(text, sock, allowedGroups, senderName) {
    const result = { ok: false, total: 0, sent: 0, failed: 0, reason: '' };
    if (!text) { result.reason = 'empty'; return result; }

    const uniqueLinks = extractUniqueLinks(text);
    result.total = uniqueLinks.length;
    if (uniqueLinks.length === 0) { result.reason = 'no_supported_link'; return result; }

    for (const link of uniqueLinks) {
        console.log(`🔗 Download attempt: ${link}`);
        let media = null;

        try {
            media = await getMedia(link);

            if (!media) {
                result.failed++;
                console.log(`❌ Download failed for: ${link} (private/expired media, geo-block, or yt-dlp needs updating)`);
                continue;
            }

            let sentForLink = false;
            for (const groupJid of allowedGroups) {
                try {
                    await sendMediaToGroup(sock, groupJid, media);
                    sentForLink = true;
                    console.log(`✅ Sent to group ${groupJid} via ${media.source}`);
                } catch (err) {
                    console.error(`❌ Send error to ${groupJid}:`, err.message);
                }
            }

            if (sentForLink) result.sent++;
            else { result.failed++; if (!result.reason) result.reason = 'send_failed'; }
        } catch (err) {
            result.failed++;
            console.error(`❌ Processing error for ${link}:`, err.message);
        } finally {
            if (media?.type === 'file' && media.path) {
                await safeUnlink(media.path);
            }
        }
    }

    result.ok = result.sent > 0;
    if (!result.ok && !result.reason) result.reason = 'download_failed';
    return result;
}

module.exports = {
    processLinksAndBroadcast,
    extractUniqueLinks,
    cleanSocialUrl,
    isSupportedUrl
};

// ai.js — multi-provider LLM client for the .ask command.
// Uses axios (already a dependency); no extra packages required.
// Default provider: Google Gemini. Also supports Anthropic and OpenAI-compatible APIs.
const axios = require('axios');

const AI_PROVIDER = String(process.env.AI_PROVIDER || 'gemini').toLowerCase();
const AI_API_KEY =
    process.env.GEMINI_API_KEY ||
    process.env.AI_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    process.env.OPENAI_API_KEY ||
    '';

const AI_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 60000);
const AI_MAX_TOKENS = Number(process.env.AI_MAX_TOKENS || 1024);
const MAX_QUESTION_CHARS = Number(process.env.AI_MAX_QUESTION_CHARS || 4000);
const AI_SYSTEM_PROMPT = process.env.AI_SYSTEM_PROMPT
    || "Tu es Salibot, un assistant WhatsApp serviable. Réponds de façon claire, concise et directe, dans la langue de la question, et repond en anglais. Évite le markdown lourd : WhatsApp n'affiche que *gras*, _italique_ et ```code```.";

const AI_MODEL = process.env.AI_MODEL || (
    AI_PROVIDER === 'openai' ? 'gpt-4o-mini'
        : AI_PROVIDER === 'anthropic' ? 'claude-haiku-4-5-20251001'
            : 'gemini-2.0-flash'
);

function isConfigured() {
    return Boolean(AI_API_KEY);
}

function apiError(message, status) {
    const err = new Error(message);
    err.code = 'API_ERROR';
    if (status) err.status = status;
    return err;
}

// ── Google Gemini (Generative Language API) ──
async function askGemini(prompt) {
    const base = process.env.AI_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta';
    const url = `${base.replace(/\/+$/, '')}/models/${encodeURIComponent(AI_MODEL)}:generateContent`;
    const body = {
        systemInstruction: { parts: [{ text: AI_SYSTEM_PROMPT }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: AI_MAX_TOKENS }
    };
    const res = await axios.post(url, body, {
        timeout: AI_TIMEOUT_MS,
        headers: { 'content-type': 'application/json', 'x-goog-api-key': AI_API_KEY },
        validateStatus: (s) => s >= 200 && s < 500
    });
    if (res.status >= 400) throw apiError(res.data?.error?.message || `HTTP ${res.status}`, res.status);

    const candidate = res.data?.candidates?.[0];
    if (!candidate) {
        const blocked = res.data?.promptFeedback?.blockReason;
        if (blocked) throw apiError(`Bloqué par les filtres de sécurité (${blocked}).`);
        return '(réponse vide)';
    }
    const parts = candidate.content?.parts || [];
    const text = parts.filter((p) => typeof p.text === 'string').map((p) => p.text).join('\n').trim();
    return text || '(réponse vide)';
}

// ── Anthropic (Claude Messages API) ──
async function askAnthropic(prompt) {
    const url = process.env.AI_BASE_URL || 'https://api.anthropic.com/v1/messages';
    const res = await axios.post(url, {
        model: AI_MODEL,
        max_tokens: AI_MAX_TOKENS,
        system: [{ type: 'text', text: AI_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
        messages: [{ role: 'user', content: prompt }]
    }, {
        timeout: AI_TIMEOUT_MS,
        headers: {
            'x-api-key': AI_API_KEY,
            'anthropic-version': process.env.ANTHROPIC_VERSION || '2023-06-01',
            'content-type': 'application/json'
        },
        validateStatus: (s) => s >= 200 && s < 500
    });
    if (res.status >= 400) throw apiError(res.data?.error?.message || `HTTP ${res.status}`, res.status);
    const blocks = Array.isArray(res.data?.content) ? res.data.content : [];
    return blocks.filter((b) => b && b.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n').trim() || '(réponse vide)';
}

// ── OpenAI-compatible (chat/completions, Bearer auth) ──
async function askOpenAI(prompt) {
    const base = process.env.AI_BASE_URL || 'https://api.openai.com/v1';
    const res = await axios.post(`${base.replace(/\/+$/, '')}/chat/completions`, {
        model: AI_MODEL,
        max_tokens: AI_MAX_TOKENS,
        messages: [
            { role: 'system', content: AI_SYSTEM_PROMPT },
            { role: 'user', content: prompt }
        ]
    }, {
        timeout: AI_TIMEOUT_MS,
        headers: { 'authorization': `Bearer ${AI_API_KEY}`, 'content-type': 'application/json' },
        validateStatus: (s) => s >= 200 && s < 500
    });
    if (res.status >= 400) throw apiError(res.data?.error?.message || `HTTP ${res.status}`, res.status);
    return (res.data?.choices?.[0]?.message?.content || '').trim() || '(réponse vide)';
}

/**
 * Ask the configured model a single question.
 * Throws Error with `.code` = 'NO_KEY' | 'EMPTY' | 'API_ERROR' | 'BLOCKED'.
 */
async function askAI(question) {
    const prompt = String(question || '').trim().slice(0, MAX_QUESTION_CHARS);
    if (!prompt) { const e = new Error('Empty question'); e.code = 'EMPTY'; throw e; }
    if (!AI_API_KEY) { const e = new Error('AI not configured'); e.code = 'NO_KEY'; throw e; }

    if (AI_PROVIDER === 'anthropic') return askAnthropic(prompt);
    if (AI_PROVIDER === 'openai') return askOpenAI(prompt);
    return askGemini(prompt);
}

module.exports = { askAI, isConfigured, AI_MODEL, AI_PROVIDER };

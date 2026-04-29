/**
 * fs-session-mailer
 *
 * POST /webhook  — receive a Fullstory session-summary webhook, generate an
 *                  AI summary via the Fullstory Sessions API, and email it
 *                  to the address supplied in the JSON body.
 *
 * Required payload fields
 *   to_email | email | recipient | recipient_email   — where to send the email
 *   device_id + session_id                           — used to call the FS summary API
 *
 * Optional payload fields
 *   session_url, user_id, user_email, duration_seconds, page_count, … any extra key
 *
 * Required env vars
 *   FS_API_KEY      — Fullstory API key (Basic auth value)
 *   FS_PROFILE_ID   — summary prompt-profile ID
 *   FS_API_BASE     — API base URL, e.g. https://api.eu1.fullstory.com
 *
 * Optional security
 *   If WEBHOOK_SECRET is set, the request must include an
 *   X-FS-Signature header containing HMAC-SHA256(secret, rawBody) in hex.
 */

import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import { createHmac, timingSafeEqual } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT           = Number(process.env.PORT)   || 3849;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const EMAIL_FROM     = process.env.EMAIL_FROM     || process.env.SMTP_USER || '';

const FS_API_KEY    = process.env.FS_API_KEY    || '';
const FS_PROFILE_ID = process.env.FS_PROFILE_ID || '';
const FS_API_BASE   = (process.env.FS_API_BASE  || 'https://api.fullstory.com').replace(/\/$/, '');

// ── Mailer ────────────────────────────────────────────────────────────────────

const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   Number(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  family: 4, // force IPv4 — Render's network has no outbound IPv6
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ── App ───────────────────────────────────────────────────────────────────────

const app = express();

app.use(
  express.json({
    limit: '4mb',
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.static(join(__dirname, 'public')));

// ── Live request feed (SSE) ───────────────────────────────────────────────────

const MAX_LOG = 100;

/** @type {import('express').Response[]} */
const sseClients = [];

/** @type {Array<object>} */
const requestLog = [];

function broadcast(obj) {
  const line = `data: ${JSON.stringify(obj)}\n\n`;
  for (const res of sseClients) {
    try { res.write(line); } catch { /* ignore */ }
  }
}

function logRequest(entry) {
  requestLog.push(entry);
  if (requestLog.length > MAX_LOG) requestLog.shift();
  broadcast({ type: 'request', entry });
}

app.get('/api/feed', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  // Disable nginx/Render proxy buffering so events arrive immediately
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();
  sseClients.push(res);
  req.on('close', () => {
    const i = sseClients.indexOf(res);
    if (i >= 0) sseClients.splice(i, 1);
  });
  res.write(`data: ${JSON.stringify({ type: 'hello', backlog: requestLog.slice(-50) })}\n\n`);

  // Send a keep-alive comment every 25 s so Render doesn't close idle connections
  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(ping); }
  }, 25000);
  req.on('close', () => clearInterval(ping));
});

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'fs-session-mailer', port: PORT });
});

// ── HMAC verification ─────────────────────────────────────────────────────────

function verifySignature(req) {
  if (!WEBHOOK_SECRET) return true;
  const sig = req.headers['x-fs-signature'];
  if (!sig) return false;
  const expected = createHmac('sha256', WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest('hex');
  try {
    return timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ── Fullstory summary API ─────────────────────────────────────────────────────

/**
 * Call the Fullstory Sessions API to generate an AI summary for the session.
 * Session ID is constructed as  device_id:session_id  (colon-separated).
 * Returns the summary string, or throws on error.
 */
async function generateFSSummary(deviceId, sessionId) {
  if (!FS_API_KEY)    throw new Error('FS_API_KEY env var is not set');
  if (!FS_PROFILE_ID) throw new Error('FS_PROFILE_ID env var is not set');

  const compositeId = encodeURIComponent(`${deviceId}:${sessionId}`);
  const url = `${FS_API_BASE}/v2/sessions/${compositeId}/summary?profile_id=${encodeURIComponent(FS_PROFILE_ID)}`;

  const ts = new Date().toISOString();
  console.log(`[${ts}] FS summary API → GET ${url}`);

  const res = await fetch(url, {
    method:  'GET',
    headers: { Authorization: `Basic ${FS_API_KEY}` },
  });

  const raw = await res.text();
  if (!res.ok) {
    throw new Error(`Fullstory API ${res.status}: ${raw}`);
  }

  // Response is { "summary": "..." }
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed.summary === 'string' ? parsed.summary : raw;
  } catch {
    return raw; // plain-text response
  }
}

// ── Email builder ─────────────────────────────────────────────────────────────

const EMAIL_FIELD_KEYS = new Set(['to_email', 'email', 'recipient', 'recipient_email']);

const SKIP_IN_TABLE = new Set([
  'to_email', 'email', 'recipient', 'recipient_email',
  'session_id', 'session_url', 'user_id', 'user_email',
  'summary', 'duration_seconds', 'page_count',
  'device_id', // internal — used for API call, not rendered
]);

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderValue(v) {
  if (v === null || v === undefined) return '<em style="color:#aaa">null</em>';
  if (typeof v === 'boolean') return `<code style="color:#c792ea">${v}</code>`;
  if (typeof v === 'number')  return `<code style="color:#f0c14a">${v}</code>`;
  if (typeof v === 'string') {
    if (/^https?:\/\//.test(v)) {
      return `<a href="${escapeHtml(v)}" style="color:#3d8bfd">${escapeHtml(v)}</a>`;
    }
    return escapeHtml(v);
  }
  return `<pre style="margin:0;font-size:12px;background:#f4f4f4;padding:6px 8px;border-radius:4px;overflow:auto">${escapeHtml(JSON.stringify(v, null, 2))}</pre>`;
}

function detailsTable(rows) {
  if (!rows.length) return '';
  const trs = rows
    .map(([k, v]) => `
      <tr>
        <td style="padding:8px 14px;font-weight:600;color:#555;white-space:nowrap;border-bottom:1px solid #eee;vertical-align:top">${escapeHtml(k)}</td>
        <td style="padding:8px 14px;color:#333;border-bottom:1px solid #eee;word-break:break-all">${renderValue(v)}</td>
      </tr>`)
    .join('');
  return `
    <table style="width:100%;border-collapse:collapse;background:#f9f9f9;border-radius:8px;overflow:hidden;font-size:14px">
      ${trs}
    </table>`;
}

function buildEmailHtml(payload, generatedSummary) {
  const { session_id, session_url, user_id, user_email, duration_seconds, page_count } = payload;

  const summary = generatedSummary || payload.summary || null;

  const knownRows = [];
  if (session_id)              knownRows.push(['Session ID', session_id]);
  if (session_url)             knownRows.push(['Session URL', session_url]);
  if (user_id)                 knownRows.push(['User ID', user_id]);
  if (user_email)              knownRows.push(['User email', user_email]);
  if (duration_seconds != null) {
    const m = Math.floor(duration_seconds / 60);
    const s = Math.round(duration_seconds % 60);
    knownRows.push(['Duration', m ? `${m}m ${s}s` : `${s}s`]);
  }
  if (page_count != null) knownRows.push(['Pages visited', page_count]);

  const extraRows = Object.entries(payload)
    .filter(([k]) => !SKIP_IN_TABLE.has(k))
    .filter(([, v]) => v !== null && v !== undefined);

  const allRows = [...knownRows, ...extraRows];

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif">
  <div style="max-width:660px;margin:36px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.10)">

    <!-- Header -->
    <div style="background:#1a2332;padding:28px 36px">
      <div style="font-size:11px;font-weight:700;letter-spacing:.08em;color:#3d8bfd;text-transform:uppercase;margin-bottom:6px">Fullstory</div>
      <h1 style="margin:0;color:#e8eef5;font-size:22px;font-weight:700">Session Summary</h1>
      ${session_id ? `<p style="margin:6px 0 0;color:#8b9cb3;font-size:13px">Session&nbsp;${escapeHtml(String(session_id))}</p>` : ''}
    </div>

    <div style="padding:28px 36px">

      <!-- AI summary -->
      ${summary ? `
      <div style="background:#f0f7ff;border-left:4px solid #3d8bfd;border-radius:6px;padding:16px 18px;margin-bottom:24px;font-size:15px;line-height:1.65;color:#333;white-space:pre-wrap">
        ${escapeHtml(String(summary))}
      </div>` : ''}

      <!-- Details table -->
      ${allRows.length ? `
      <h2 style="color:#333;font-size:16px;margin:0 0 10px">Details</h2>
      ${detailsTable(allRows)}` : ''}

    </div>

    <!-- Footer -->
    <div style="padding:18px 36px;border-top:1px solid #eee;color:#bbb;font-size:11px">
      Sent by fs-session-mailer &bull; ${new Date().toUTCString()}
    </div>
  </div>
</body>
</html>`;
}

function buildTextBody(payload, generatedSummary) {
  const summary = generatedSummary || payload.summary || null;
  const lines = ['Fullstory Session Summary', '=========================', ''];
  if (summary) lines.push(summary, '');
  for (const [k, v] of Object.entries(payload)) {
    if (SKIP_IN_TABLE.has(k) || EMAIL_FIELD_KEYS.has(k)) continue;
    lines.push(`${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
  }
  return lines.join('\n');
}

// ── Core send logic (shared by /webhook and /test) ───────────────────────────

async function sendSessionEmail(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    const e = new Error('Request body must be a JSON object');
    e.status = 400;
    throw e;
  }

  const toEmail =
    body.to_email        ||
    body.email           ||
    body.recipient       ||
    body.recipient_email;

  if (!toEmail || typeof toEmail !== 'string' || !toEmail.includes('@')) {
    const e = new Error(
      'Payload must include a valid email in one of: to_email, email, recipient, recipient_email',
    );
    e.status = 400;
    throw e;
  }

  // Generate summary via Fullstory API when device_id + session_id are present
  let generatedSummary = null;
  const deviceId  = body.device_id;
  const sessionId = body.session_id || body.sessionId;

  if (deviceId && sessionId) {
    try {
      generatedSummary = await generateFSSummary(deviceId, sessionId);
      const ts = new Date().toISOString();
      console.log(`[${ts}] FS summary generated  session=${deviceId}:${sessionId}`);
    } catch (err) {
      // Non-fatal: log and fall back to payload's summary field (if any)
      console.warn(`[${new Date().toISOString()}] FS summary failed: ${err.message}`);
    }
  }

  const subject = sessionId
    ? `Fullstory Session Summary – ${sessionId}`
    : 'Fullstory Session Summary';

  await transporter.sendMail({
    from:    EMAIL_FROM,
    to:      toEmail,
    subject,
    html:    buildEmailHtml(body, generatedSummary),
    text:    buildTextBody(body, generatedSummary),
  });

  const ts = new Date().toISOString();
  console.log(`[${ts}] email sent  to=${toEmail}  session=${sessionId ?? 'n/a'}`);
  return { ok: true, to: toEmail, session_id: sessionId ?? null };
}

// ── Webhook endpoint ──────────────────────────────────────────────────────────

app.post('/webhook', async (req, res) => {
  if (!verifySignature(req)) {
    return res.status(401).json({ ok: false, error: 'Invalid or missing X-FS-Signature header' });
  }

  const receivedAt = new Date().toISOString();
  let result, error;

  try {
    result = await sendSessionEmail(req.body);
    res.json(result);
  } catch (err) {
    console.error(`[${new Date().toISOString()}] webhook error: ${err.message}`);
    error = err.message;
    res.status(err.status || 502).json({ ok: false, error: err.message });
  }

  logRequest({
    id:         Math.random().toString(36).slice(2),
    source:     'webhook',
    receivedAt,
    body:       req.body,
    ok:         !error,
    to:         result?.to ?? null,
    session_id: result?.session_id ?? null,
    error:      error ?? null,
  });
});

// ── Test-fire endpoint (dev only) ─────────────────────────────────────────────

app.post('/test', async (req, res) => {
  const overrides = req.body || {};
  const sample = {
    to_email:         overrides.to_email   || 'you@example.com',
    device_id:        overrides.device_id  || null,
    session_id:       overrides.session_id || null,
    session_url:      overrides.session_url || null,
    user_id:          overrides.user_id    || null,
    user_email:       overrides.user_email || null,
    duration_seconds: overrides.duration_seconds ?? null,
    page_count:       overrides.page_count ?? null,
    ...overrides,
  };

  // Strip nulls from sample so the email isn't cluttered
  for (const k of Object.keys(sample)) {
    if (sample[k] === null) delete sample[k];
  }

  const receivedAt = new Date().toISOString();
  let result, error;

  try {
    result = await sendSessionEmail(sample);
    res.json(result);
  } catch (err) {
    error = err.message;
    res.status(err.status || 502).json({ ok: false, error: err.message });
  }

  logRequest({
    id:         Math.random().toString(36).slice(2),
    source:     'test',
    receivedAt,
    body:       sample,
    ok:         !error,
    to:         result?.to ?? null,
    session_id: result?.session_id ?? null,
    error:      error ?? null,
  });
});

// ── JSON error handler ────────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  const status  = err.status || err.statusCode || 500;
  const message = err.expose !== false && err.message ? err.message : 'Internal server error';
  console.error(`[${new Date().toISOString()}] unhandled error ${status}: ${err.message}`);
  res.status(status).json({ ok: false, error: message });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`fs-session-mailer running on http://localhost:${PORT}`);
  console.log(`Webhook endpoint: POST http://localhost:${PORT}/webhook`);
  console.log(`FS API base: ${FS_API_BASE}  profile: ${FS_PROFILE_ID || '(not set)'}`);

  const SELF_URL = process.env.RENDER_EXTERNAL_URL;
  if (SELF_URL) {
    setInterval(() => {
      fetch(`${SELF_URL}/health`)
        .then(() => console.log(`[${new Date().toISOString()}] keep-alive ping ok`))
        .catch((e) => console.warn(`[${new Date().toISOString()}] keep-alive ping failed: ${e.message}`));
    }, 10 * 60 * 1000);
    console.log(`Keep-alive ping active → ${SELF_URL}/health every 10 min`);
  }
});

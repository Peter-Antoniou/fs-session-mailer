/**
 * fs-session-mailer
 *
 * POST /webhook  — receive a Fullstory webhook, generate an AI summary via
 *                  the Fullstory Sessions API, and email it to the address
 *                  in the payload.
 *
 * Required payload fields
 *   to_email | email | recipient | recipient_email   — where to send the email
 *   device_id + session_id                           — used to call the FS summary API
 *
 * Required env vars
 *   FS_API_KEY, FS_PROFILE_ID, FS_API_BASE
 *   SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS
 */

import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import { createHmac, timingSafeEqual } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Config ────────────────────────────────────────────────────────────────────

const PORT           = Number(process.env.PORT)   || 3849;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const EMAIL_FROM     = process.env.EMAIL_FROM     || process.env.SMTP_USER || '';

const FS_API_KEY    = process.env.FS_API_KEY    || '';
const FS_PROFILE_ID = process.env.FS_PROFILE_ID || '';
const FS_API_BASE   = (process.env.FS_API_BASE  || 'https://api.fullstory.com').replace(/\/$/, '');

// ── Logger ────────────────────────────────────────────────────────────────────

function log(level, msg, extra) {
  const ts = new Date().toISOString();
  const line = extra !== undefined
    ? `[${ts}] [${level}] ${msg} ${typeof extra === 'string' ? extra : JSON.stringify(extra)}`
    : `[${ts}] [${level}] ${msg}`;
  if (level === 'ERROR') console.error(line);
  else if (level === 'WARN')  console.warn(line);
  else console.log(line);
}

const info  = (msg, extra) => log('INFO',  msg, extra);
const warn  = (msg, extra) => log('WARN',  msg, extra);
const error = (msg, extra) => log('ERROR', msg, extra);

// ── Mailer ────────────────────────────────────────────────────────────────────

const smtpConfig = {
  host:   process.env.SMTP_HOST,
  port:   Number(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  family: 4, // force IPv4 — Render has no outbound IPv6
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
};

const transporter = nodemailer.createTransport(smtpConfig);

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
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();
  sseClients.push(res);
  req.on('close', () => {
    const i = sseClients.indexOf(res);
    if (i >= 0) sseClients.splice(i, 1);
  });
  res.write(`data: ${JSON.stringify({ type: 'hello', backlog: requestLog.slice(-50) })}\n\n`);

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

async function generateFSSummary(deviceId, sessionId) {
  if (!FS_API_KEY)    throw new Error('FS_API_KEY env var is not set');
  if (!FS_PROFILE_ID) throw new Error('FS_PROFILE_ID env var is not set');

  const compositeId = encodeURIComponent(`${deviceId}:${sessionId}`);
  const url = `${FS_API_BASE}/v2/sessions/${compositeId}/summary?profile_id=${encodeURIComponent(FS_PROFILE_ID)}`;

  info(`FS API  →  GET ${url}`);

  const res = await fetch(url, {
    method:  'GET',
    headers: { Authorization: `Basic ${FS_API_KEY}` },
  });

  const raw = await res.text();
  info(`FS API  ←  status=${res.status}  body=${raw.slice(0, 300)}`);

  if (!res.ok) {
    throw new Error(`Fullstory API ${res.status}: ${raw}`);
  }

  try {
    const parsed = JSON.parse(raw);
    const summary = typeof parsed.summary === 'string' ? parsed.summary : raw;
    info(`FS API  summary length=${summary.length} chars`);
    return summary;
  } catch {
    return raw;
  }
}

// ── Email builder ─────────────────────────────────────────────────────────────

const EMAIL_FIELD_KEYS = new Set(['to_email', 'email', 'recipient', 'recipient_email']);

const SKIP_IN_TABLE = new Set([
  'to_email', 'email', 'recipient', 'recipient_email',
  'session_id', 'session_url', 'user_id', 'user_email',
  'summary', 'duration_seconds', 'page_count',
  'device_id',
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
  if (session_id)               knownRows.push(['Session ID', session_id]);
  if (session_url)              knownRows.push(['Session URL', session_url]);
  if (user_id)                  knownRows.push(['User ID', user_id]);
  if (user_email)               knownRows.push(['User email', user_email]);
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
    <div style="background:#1a2332;padding:28px 36px">
      <div style="font-size:11px;font-weight:700;letter-spacing:.08em;color:#3d8bfd;text-transform:uppercase;margin-bottom:6px">Fullstory</div>
      <h1 style="margin:0;color:#e8eef5;font-size:22px;font-weight:700">Session Summary</h1>
      ${session_id ? `<p style="margin:6px 0 0;color:#8b9cb3;font-size:13px">Session&nbsp;${escapeHtml(String(session_id))}</p>` : ''}
    </div>
    <div style="padding:28px 36px">
      ${summary ? `
      <div style="background:#f0f7ff;border-left:4px solid #3d8bfd;border-radius:6px;padding:16px 18px;margin-bottom:24px;font-size:15px;line-height:1.65;color:#333;white-space:pre-wrap">
        ${escapeHtml(String(summary))}
      </div>` : ''}
      ${allRows.length ? `
      <h2 style="color:#333;font-size:16px;margin:0 0 10px">Details</h2>
      ${detailsTable(allRows)}` : ''}
    </div>
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

// ── Core send logic ───────────────────────────────────────────────────────────

async function sendSessionEmail(body) {
  // ── 1. Validate body ──────────────────────────────────────────────────────
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    error('Body validation failed — not a JSON object', { body });
    const e = new Error('Request body must be a JSON object');
    e.status = 400;
    throw e;
  }

  info(`Body received  keys=[${Object.keys(body).join(', ')}]`);

  // ── 2. Resolve recipient ───────────────────────────────────────────────────
  const toEmail =
    body.to_email        ||
    body.email           ||
    body.recipient       ||
    body.recipient_email;

  if (!toEmail || typeof toEmail !== 'string' || !toEmail.includes('@')) {
    error('No valid recipient email found in payload', {
      checked: ['to_email', 'email', 'recipient', 'recipient_email'],
      values:  {
        to_email:        body.to_email,
        email:           body.email,
        recipient:       body.recipient,
        recipient_email: body.recipient_email,
      },
    });
    const e = new Error(
      'Payload must include a valid email in one of: to_email, email, recipient, recipient_email',
    );
    e.status = 400;
    throw e;
  }

  info(`Recipient resolved  to=${toEmail}`);

  // ── 3. Generate summary via Fullstory API ──────────────────────────────────
  let generatedSummary = null;
  const deviceId  = body.device_id;
  const sessionId = body.session_id || body.sessionId;

  info(`Session fields  device_id=${deviceId ?? '(missing)'}  session_id=${sessionId ?? '(missing)'}`);

  if (deviceId && sessionId) {
    info(`Calling Fullstory summary API  composite=${deviceId}:${sessionId}`);
    try {
      generatedSummary = await generateFSSummary(deviceId, sessionId);
      info(`Summary generated successfully  length=${generatedSummary.length} chars`);
    } catch (err) {
      warn(`Summary generation failed (non-fatal, continuing without summary)  error=${err.message}`);
    }
  } else {
    warn('Skipping summary API call — device_id and/or session_id missing from payload');
  }

  // ── 4. Build and send email ────────────────────────────────────────────────
  const subject = sessionId
    ? `Fullstory Session Summary – ${sessionId}`
    : 'Fullstory Session Summary';

  info(`Sending email  from="${EMAIL_FROM}"  to=${toEmail}  subject="${subject}"  smtp=${smtpConfig.host}:${smtpConfig.port}  secure=${smtpConfig.secure}`);

  let mailResult;
  try {
    mailResult = await transporter.sendMail({
      from:    EMAIL_FROM,
      to:      toEmail,
      subject,
      html:    buildEmailHtml(body, generatedSummary),
      text:    buildTextBody(body, generatedSummary),
    });
  } catch (err) {
    error(`SMTP sendMail failed  code=${err.code}  command=${err.command}  message=${err.message}`);
    if (err.response) error(`SMTP server response: ${err.response}`);
    throw err;
  }

  info(`Email sent  messageId=${mailResult.messageId}  accepted=${JSON.stringify(mailResult.accepted)}  rejected=${JSON.stringify(mailResult.rejected)}`);
  return { ok: true, to: toEmail, session_id: sessionId ?? null };
}

// ── Webhook endpoint ──────────────────────────────────────────────────────────

app.post('/webhook', async (req, res) => {
  const receivedAt = new Date().toISOString();
  info(`POST /webhook  ip=${req.ip}  content-type="${req.headers['content-type']}"  content-length=${req.headers['content-length'] ?? '?'}`);

  // Signature check
  if (!WEBHOOK_SECRET) {
    info('Signature check skipped — WEBHOOK_SECRET not configured');
  } else {
    const passed = verifySignature(req);
    info(`Signature check  passed=${passed}`);
    if (!passed) {
      error('Request rejected — invalid or missing X-FS-Signature header');
      return res.status(401).json({ ok: false, error: 'Invalid or missing X-FS-Signature header' });
    }
  }

  let result, reqError;

  try {
    result = await sendSessionEmail(req.body);
    res.json(result);
  } catch (err) {
    error(`sendSessionEmail threw  status=${err.status ?? 502}  message=${err.message}`);
    reqError = err.message;
    res.status(err.status || 502).json({ ok: false, error: err.message });
  }

  logRequest({
    id:         Math.random().toString(36).slice(2),
    source:     'webhook',
    receivedAt,
    body:       req.body,
    ok:         !reqError,
    to:         result?.to ?? null,
    session_id: result?.session_id ?? null,
    error:      reqError ?? null,
  });
});

// ── Test-fire endpoint ────────────────────────────────────────────────────────

app.post('/test', async (req, res) => {
  info('POST /test  building sample payload from overrides');
  const overrides = req.body || {};
  const sample = {
    to_email:         overrides.to_email        || 'you@example.com',
    device_id:        overrides.device_id       || null,
    session_id:       overrides.session_id      || null,
    session_url:      overrides.session_url     || null,
    user_id:          overrides.user_id         || null,
    user_email:       overrides.user_email      || null,
    duration_seconds: overrides.duration_seconds ?? null,
    page_count:       overrides.page_count      ?? null,
    ...overrides,
  };

  for (const k of Object.keys(sample)) {
    if (sample[k] === null) delete sample[k];
  }

  info(`Test payload keys=[${Object.keys(sample).join(', ')}]`);

  const receivedAt = new Date().toISOString();
  let result, reqError;

  try {
    result = await sendSessionEmail(sample);
    res.json(result);
  } catch (err) {
    reqError = err.message;
    res.status(err.status || 502).json({ ok: false, error: err.message });
  }

  logRequest({
    id:         Math.random().toString(36).slice(2),
    source:     'test',
    receivedAt,
    body:       sample,
    ok:         !reqError,
    to:         result?.to ?? null,
    session_id: result?.session_id ?? null,
    error:      reqError ?? null,
  });
});

// ── JSON error handler ────────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  const status  = err.status || err.statusCode || 500;
  const message = err.expose !== false && err.message ? err.message : 'Internal server error';
  error(`Unhandled Express error  status=${status}  message=${err.message}`);
  res.status(status).json({ ok: false, error: message });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, async () => {
  info('═══════════════════════════════════════════════');
  info(`fs-session-mailer starting on port ${PORT}`);
  info('───────────────────────────────────────────────');
  info(`SMTP host:      ${smtpConfig.host ?? '(not set)'}`);
  info(`SMTP port:      ${smtpConfig.port}`);
  info(`SMTP secure:    ${smtpConfig.secure}`);
  info(`SMTP user:      ${smtpConfig.auth.user ?? '(not set)'}`);
  info(`SMTP pass:      ${smtpConfig.auth.pass ? '(set)' : '(NOT SET)'}`);
  info(`EMAIL_FROM:     ${EMAIL_FROM || '(not set)'}`);
  info('───────────────────────────────────────────────');
  info(`FS_API_BASE:    ${FS_API_BASE}`);
  info(`FS_PROFILE_ID:  ${FS_PROFILE_ID || '(NOT SET)'}`);
  info(`FS_API_KEY:     ${FS_API_KEY ? '(set)' : '(NOT SET)'}`);
  info(`WEBHOOK_SECRET: ${WEBHOOK_SECRET ? '(set)' : '(not set — all requests accepted)'}`);
  info('───────────────────────────────────────────────');

  // Verify SMTP connection on startup so config errors surface immediately
  info('Verifying SMTP connection…');
  try {
    await transporter.verify();
    info('SMTP connection verified OK');
  } catch (err) {
    error(`SMTP connection FAILED  code=${err.code}  message=${err.message}`);
    if (err.response) error(`SMTP server said: ${err.response}`);
  }

  info('═══════════════════════════════════════════════');

  const SELF_URL = process.env.RENDER_EXTERNAL_URL;
  if (SELF_URL) {
    setInterval(() => {
      fetch(`${SELF_URL}/health`)
        .then(() => info('Keep-alive ping ok'))
        .catch((e) => warn(`Keep-alive ping failed  ${e.message}`));
    }, 10 * 60 * 1000);
    info(`Keep-alive ping active → ${SELF_URL}/health every 10 min`);
  }
});

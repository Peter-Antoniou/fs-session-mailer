/**
 * fs-session-mailer
 *
 * POST /webhook  — receive a Fullstory session-summary webhook and email it
 *                  to the address supplied in the payload.
 *
 * Required payload fields
 *   to_email | email | recipient | recipient_email   — where to send the email
 *
 * Optional payload fields (all are rendered if present)
 *   session_id, session_url, user_id, user_email, summary,
 *   duration_seconds, page_count, events[], … any extra key
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

const PORT            = Number(process.env.PORT)            || 3849;
const WEBHOOK_SECRET  = process.env.WEBHOOK_SECRET          || '';
const EMAIL_FROM      = process.env.EMAIL_FROM              || process.env.SMTP_USER || '';

// ── Mailer ────────────────────────────────────────────────────────────────────

const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   Number(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
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

// ── Email builder ─────────────────────────────────────────────────────────────

const EMAIL_FIELD_KEYS = new Set(['to_email', 'email', 'recipient', 'recipient_email']);

const KNOWN_FIELDS = [
  'session_id', 'session_url', 'user_id', 'user_email',
  'summary', 'duration_seconds', 'page_count', 'events',
];

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

function buildEmailHtml(payload) {
  const {
    session_id,
    session_url,
    user_id,
    user_email,
    summary,
    duration_seconds,
    page_count,
    events,
    ...extra
  } = payload;

  // Build detail rows from known fields
  const knownRows = [];
  if (session_id)         knownRows.push(['Session ID', session_id]);
  if (session_url)        knownRows.push(['Session URL', session_url]);
  if (user_id)            knownRows.push(['User ID', user_id]);
  if (user_email)         knownRows.push(['User email', user_email]);
  if (duration_seconds != null) {
    const m = Math.floor(duration_seconds / 60);
    const s = Math.round(duration_seconds % 60);
    knownRows.push(['Duration', m ? `${m}m ${s}s` : `${s}s`]);
  }
  if (page_count != null) knownRows.push(['Pages visited', page_count]);

  // Append any extra scalar fields from the payload
  const extraRows = Object.entries(extra)
    .filter(([k]) => !EMAIL_FIELD_KEYS.has(k))
    .filter(([, v]) => v !== null && v !== undefined);

  const allRows = [...knownRows, ...extraRows];

  // Events section (capped at 30)
  let eventsHtml = '';
  if (Array.isArray(events) && events.length) {
    const shown = events.slice(0, 30);
    const more  = events.length - shown.length;
    eventsHtml = `
      <h2 style="color:#333;font-size:16px;margin:28px 0 10px">
        Events <span style="font-weight:400;color:#999;font-size:13px">(${events.length})</span>
      </h2>
      <ol style="margin:0;padding-left:20px;color:#555;line-height:1.9;font-size:13px">
        ${shown.map((e) => `<li>${typeof e === 'string' ? escapeHtml(e) : escapeHtml(JSON.stringify(e))}</li>`).join('')}
        ${more ? `<li style="color:#aaa">… and ${more} more</li>` : ''}
      </ol>`;
  }

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

      <!-- AI / narrative summary -->
      ${summary ? `
      <div style="background:#f0f7ff;border-left:4px solid #3d8bfd;border-radius:6px;padding:16px 18px;margin-bottom:24px;font-size:15px;line-height:1.65;color:#333">
        ${escapeHtml(String(summary))}
      </div>` : ''}

      <!-- Details table -->
      ${allRows.length ? `
      <h2 style="color:#333;font-size:16px;margin:0 0 10px">Details</h2>
      ${detailsTable(allRows)}` : ''}

      <!-- Events -->
      ${eventsHtml}

    </div>

    <!-- Footer -->
    <div style="padding:18px 36px;border-top:1px solid #eee;color:#bbb;font-size:11px">
      Sent by fs-session-mailer &bull; ${new Date().toUTCString()}
    </div>
  </div>
</body>
</html>`;
}

function buildTextBody(payload) {
  const lines = ['Fullstory Session Summary', '=========================', ''];
  if (payload.summary) lines.push(String(payload.summary), '');
  for (const [k, v] of Object.entries(payload)) {
    if (EMAIL_FIELD_KEYS.has(k)) continue;
    lines.push(`${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
  }
  return lines.join('\n');
}

// ── Webhook endpoint ──────────────────────────────────────────────────────────

app.post('/webhook', async (req, res) => {
  if (!verifySignature(req)) {
    return res.status(401).json({ ok: false, error: 'Invalid or missing X-FS-Signature header' });
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ ok: false, error: 'Request body must be a JSON object' });
  }

  const toEmail =
    body.to_email        ||
    body.email           ||
    body.recipient       ||
    body.recipient_email;

  if (!toEmail || typeof toEmail !== 'string' || !toEmail.includes('@')) {
    return res.status(400).json({
      ok:    false,
      error: 'Payload must include a valid email in one of: to_email, email, recipient, recipient_email',
    });
  }

  const sessionId = body.session_id || body.sessionId || null;
  const subject   = sessionId
    ? `Fullstory Session Summary – ${sessionId}`
    : 'Fullstory Session Summary';

  try {
    await transporter.sendMail({
      from:    EMAIL_FROM,
      to:      toEmail,
      subject,
      html:    buildEmailHtml(body),
      text:    buildTextBody(body),
    });

    const ts = new Date().toISOString();
    console.log(`[${ts}] email sent  to=${toEmail}  session=${sessionId ?? 'n/a'}`);
    res.json({ ok: true, to: toEmail, session_id: sessionId });
  } catch (err) {
    const ts = new Date().toISOString();
    console.error(`[${ts}] email failed  to=${toEmail}  error=${err.message}`);
    res.status(502).json({ ok: false, error: err.message });
  }
});

// ── Test-fire endpoint (dev only) ─────────────────────────────────────────────

app.post('/test', express.json(), async (req, res) => {
  const overrides = req.body || {};
  const sample = {
    to_email:         overrides.to_email  || 'you@example.com',
    session_id:       overrides.session_id || 'demo-abc123',
    session_url:      'https://app.fullstory.com/ui/YOUR_ORG/sessions/demo-abc123',
    user_id:          'user_9876',
    user_email:       'alice@example.com',
    summary:          'The user landed on the pricing page, compared the Pro and Enterprise tiers, then navigated to checkout. They entered payment details but abandoned after seeing the annual total.',
    duration_seconds: 187,
    page_count:       4,
    events: [
      'Page view: /pricing',
      'Click: "Compare plans"',
      'Page view: /checkout',
      'Form interaction: payment fields',
      'Rage click: "Apply coupon"',
      'Page exit',
    ],
    ...overrides,
  };

  // Forward internally to the real webhook handler
  const { default: http } = await import('http');
  const payload = JSON.stringify(sample);
  const options = {
    hostname: '127.0.0.1',
    port:     PORT,
    path:     '/webhook',
    method:   'POST',
    headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    let data = '';
    proxyRes.on('data', (chunk) => { data += chunk; });
    proxyRes.on('end',  () => {
      try { res.status(proxyRes.statusCode).json(JSON.parse(data)); }
      catch { res.status(proxyRes.statusCode).send(data); }
    });
  });
  proxyReq.on('error', (e) => res.status(500).json({ ok: false, error: e.message }));
  proxyReq.write(payload);
  proxyReq.end();
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`fs-session-mailer running on http://localhost:${PORT}`);
  console.log(`Webhook endpoint: POST http://localhost:${PORT}/webhook`);
});

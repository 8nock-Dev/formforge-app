require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { rateLimit } = require('express-rate-limit');
const { pool, initDb } = require('./db');
const { assertSafeUrl, escapeCsv, newToken, sha256, signWebhook } = require('./security');
const { sendEmail } = require('./mailer');

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use('/api', cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5174', credentials: true }));
app.use('/f', cors({ origin: true }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
const submitLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer /, '');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Authentication required' }); }
}
const issueToken = (user) => jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !name || !password || password.length < 8) return res.status(400).json({ error: 'Name, email and an 8+ character password are required' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query('INSERT INTO users(email,password_hash,name) VALUES($1,$2,$3) RETURNING id,email,name', [email.toLowerCase(), hash, name.trim()]);
    res.status(201).json({ token: issueToken(rows[0]), user: rows[0] });
  } catch (error) { res.status(error.code === '23505' ? 409 : 500).json({ error: error.code === '23505' ? 'Email already registered' : 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [String(req.body.email || '').toLowerCase()]);
  if (!rows.length || !await bcrypt.compare(String(req.body.password || ''), rows[0].password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  const user = { id: rows[0].id, email: rows[0].email, name: rows[0].name };
  res.json({ token: issueToken(user), user });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const genericResponse = { message: 'If an account exists for that email, a password reset link has been sent.' };
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const { rows } = await pool.query('SELECT id,email,name FROM users WHERE email=$1', [email]);
    if (!rows.length) return res.json(genericResponse);
    const user = rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      `INSERT INTO password_reset_tokens(user_id,token_hash,expires_at)
       VALUES($1,$2,NOW()+INTERVAL '30 minutes')
       ON CONFLICT(user_id) DO UPDATE SET token_hash=$2,expires_at=NOW()+INTERVAL '30 minutes',created_at=NOW()`,
      [user.id,sha256(token)]
    );
    const resetUrl = `${process.env.APP_URL || 'http://localhost:5174'}/reset-password?token=${token}`;
    await sendEmail({
      to: user.email,
      subject: 'Reset your FormForge password',
      html: `<p>Hello ${escapeHtml(user.name)},</p><p>Use the link below to reset your password. It expires in 30 minutes and can only be used once.</p><p><a href="${resetUrl}">Reset password</a></p><p>If you did not request this, you can ignore this email.</p>`,
    });
    res.json(genericResponse);
  } catch (error) {
    console.error('[Auth/forgot-password]', error.message);
    res.json(genericResponse);
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (!token || password.length < 8) return res.status(400).json({ error: 'A valid token and password of at least 8 characters are required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'DELETE FROM password_reset_tokens WHERE token_hash=$1 AND expires_at>NOW() RETURNING user_id',
      [sha256(token)]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This reset link is invalid or has expired' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await client.query('UPDATE users SET password_hash=$1 WHERE id=$2', [passwordHash,rows[0].user_id]);
    await client.query('COMMIT');
    res.json({ message: 'Password reset successfully. You can now sign in.' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('[Auth/reset-password]', error.message);
    res.status(500).json({ error: 'Unable to reset password' });
  } finally { client.release(); }
});

app.get('/api/forms', authenticate, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT f.id,f.name,f.token_prefix,f.schema,f.allowed_origins,f.redirect_url,f.notify_email,f.webhook_url,
      f.retention_days,f.is_active,f.created_at,COUNT(s.id)::int AS submission_count
     FROM forms f LEFT JOIN submissions s ON s.form_id=f.id WHERE f.user_id=$1 GROUP BY f.id ORDER BY f.created_at DESC`, [req.user.userId]);
  res.json(rows);
});

function validateSchema(schema) {
  if (!Array.isArray(schema) || schema.length > 100) return false;
  const names = new Set();
  return schema.every((field) => {
    const valid = field && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(field.name) && ['text','email','number','boolean','textarea'].includes(field.type);
    if (!valid || names.has(field.name)) return false;
    names.add(field.name); return true;
  });
}

app.post('/api/forms', authenticate, async (req, res) => {
  const { name, schema = [], allowed_origins = [], redirect_url, notify_email, webhook_url, retention_days = 365 } = req.body;
  if (!name?.trim() || !validateSchema(schema)) return res.status(400).json({ error: 'A name and valid field schema are required' });
  if (!Array.isArray(allowed_origins) || allowed_origins.length > 20) return res.status(400).json({ error: 'allowed_origins must be an array with at most 20 entries' });
  try {
    if (redirect_url) await assertSafeUrl(redirect_url);
    if (webhook_url) await assertSafeUrl(webhook_url);
  } catch (error) { return res.status(400).json({ error: error.message }); }
  const token = newToken();
  const webhookSecret = webhook_url ? crypto.randomBytes(32).toString('hex') : null;
  const { rows } = await pool.query(
    `INSERT INTO forms(user_id,name,token_hash,token_prefix,schema,allowed_origins,redirect_url,notify_email,webhook_url,webhook_secret,retention_days)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,name,schema,allowed_origins,retention_days,is_active`,
    [req.user.userId,name.trim(),sha256(token),token.slice(0,10),JSON.stringify(schema),JSON.stringify(allowed_origins),redirect_url||null,notify_email||null,webhook_url||null,webhookSecret,retention_days]);
  res.status(201).json({ ...rows[0], token, webhook_secret: webhookSecret });
});

app.put('/api/forms/:id', authenticate, async (req, res) => {
  const { name, schema, allowed_origins, redirect_url, notify_email, webhook_url, retention_days, is_active } = req.body;
  if (schema && !validateSchema(schema)) return res.status(400).json({ error: 'Invalid field schema' });
  if (allowed_origins && (!Array.isArray(allowed_origins) || allowed_origins.length > 20)) return res.status(400).json({ error: 'Invalid allowed_origins' });
  try { if (redirect_url) await assertSafeUrl(redirect_url); if (webhook_url) await assertSafeUrl(webhook_url); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const currentForm = await pool.query('SELECT webhook_secret FROM forms WHERE id=$1 AND user_id=$2', [req.params.id,req.user.userId]);
  if (!currentForm.rows.length) return res.status(404).json({ error: 'Form not found' });
  const newWebhookSecret = webhook_url && !currentForm.rows[0].webhook_secret ? crypto.randomBytes(32).toString('hex') : null;
  const { rows } = await pool.query(
    `UPDATE forms SET name=COALESCE($1,name),schema=COALESCE($2,schema),allowed_origins=COALESCE($3,allowed_origins),
      redirect_url=$4,notify_email=$5,webhook_url=$6,
      webhook_secret=CASE WHEN $6::text IS NULL THEN NULL WHEN webhook_secret IS NULL THEN $11 ELSE webhook_secret END,
      retention_days=COALESCE($7,retention_days),is_active=COALESCE($8,is_active),updated_at=NOW()
     WHERE id=$9 AND user_id=$10 RETURNING id,name,schema,allowed_origins,redirect_url,notify_email,webhook_url,retention_days,is_active`,
    [name?.trim()||null,schema?JSON.stringify(schema):null,allowed_origins?JSON.stringify(allowed_origins):null,redirect_url||null,notify_email||null,webhook_url||null,retention_days,is_active,req.params.id,req.user.userId,newWebhookSecret]);
  if (!rows.length) return res.status(404).json({ error: 'Form not found' });
  res.json({ ...rows[0], ...(newWebhookSecret && webhook_url ? { webhook_secret: newWebhookSecret } : {}) });
});

app.delete('/api/forms/:id', authenticate, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM forms WHERE id=$1 AND user_id=$2',[req.params.id,req.user.userId]);
  res.status(rowCount?204:404).end();
});

app.post('/api/forms/:id/rotate-token', authenticate, async (req, res) => {
  const token = newToken();
  const { rows } = await pool.query('UPDATE forms SET token_hash=$1,token_prefix=$2,updated_at=NOW() WHERE id=$3 AND user_id=$4 RETURNING id', [sha256(token),token.slice(0,10),req.params.id,req.user.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Form not found' });
  res.json({ token });
});

app.post('/api/forms/:id/rotate-webhook-secret', authenticate, async (req, res) => {
  const secret = crypto.randomBytes(32).toString('hex');
  const { rows } = await pool.query(
    'UPDATE forms SET webhook_secret=$1,updated_at=NOW() WHERE id=$2 AND user_id=$3 AND webhook_url IS NOT NULL RETURNING id',
    [secret,req.params.id,req.user.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Form with an enabled webhook not found' });
  res.json({ webhook_secret: secret });
});

app.get('/api/forms/:id/submissions', authenticate, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT s.* FROM submissions s JOIN forms f ON f.id=s.form_id WHERE f.id=$1 AND f.user_id=$2 ORDER BY s.created_at DESC LIMIT 200`,
    [req.params.id,req.user.userId]);
  res.json(rows);
});

app.get('/api/forms/:id/submissions.csv', authenticate, async (req, res) => {
  const form = await pool.query('SELECT schema FROM forms WHERE id=$1 AND user_id=$2', [req.params.id,req.user.userId]);
  if (!form.rows.length) return res.status(404).json({ error: 'Form not found' });
  const fields = form.rows[0].schema.map((field) => field.name);
  const { rows } = await pool.query('SELECT id,data,is_spam,created_at FROM submissions WHERE form_id=$1 ORDER BY created_at DESC', [req.params.id]);
  const csv = [['id','created_at','is_spam',...fields].map(escapeCsv).join(','), ...rows.map((row) => [row.id,row.created_at.toISOString(),row.is_spam,...fields.map((name) => row.data[name])].map(escapeCsv).join(','))].join('\n');
  res.type('text/csv').attachment('submissions.csv').send(csv);
});

app.delete('/api/forms/:formId/submissions/:id', authenticate, async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM submissions s USING forms f WHERE s.id=$1 AND s.form_id=f.id AND f.id=$2 AND f.user_id=$3`, [req.params.id,req.params.formId,req.user.userId]);
  res.status(rowCount ? 204 : 404).end();
});

function validateSubmission(schema, data) {
  const allowed = new Set(schema.map((field) => field.name));
  const clean = {};
  for (const field of schema) {
    const value = data[field.name];
    if (field.required && (value === undefined || value === null || value === '')) throw new Error(`${field.name} is required`);
    if (value === undefined) continue;
    if (field.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value))) throw new Error(`${field.name} must be an email`);
    if (field.type === 'number' && !Number.isFinite(Number(value))) throw new Error(`${field.name} must be a number`);
    clean[field.name] = String(value).slice(0,10000);
  }
  Object.keys(data).filter((key) => !key.startsWith('_') && !allowed.has(key)).forEach(() => { throw new Error('Submission contains unknown fields'); });
  return clean;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g,(char)=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[char]);
}

async function sendSubmissionEmail(form, submission) {
  if (!form.notify_email || !process.env.SMTP_HOST) return;
  const transport = nodemailer.createTransport({ host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:process.env.SMTP_SECURE==='true',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS} });
  const rows = Object.entries(submission.data).map(([key,value])=>`<tr><th align="left">${escapeHtml(key)}</th><td>${escapeHtml(value)}</td></tr>`).join('');
  await transport.sendMail({ from:process.env.SMTP_FROM||process.env.SMTP_USER,to:form.notify_email,subject:`New ${form.name} submission`,html:`<h2>New ${escapeHtml(form.name)} submission</h2><table>${rows}</table>` });
}

app.options('/f/:token', (req, res) => res.sendStatus(204));
app.post('/f/:token', submitLimiter, async (req, res) => {
  const formResult = await pool.query('SELECT * FROM forms WHERE token_hash=$1 AND is_active=true', [sha256(req.params.token)]);
  if (!formResult.rows.length) return res.status(404).json({ error: 'Form endpoint not found' });
  const form = formResult.rows[0];
  const origin = req.headers.origin;
  if (origin && form.allowed_origins.length && !form.allowed_origins.includes(origin)) return res.status(403).json({ error: 'Origin not allowed' });
  const isSpam = Boolean(req.body._honeypot);
  let data; try { data = validateSubmission(form.schema, req.body); }
  catch (error) { return res.status(422).json({ error: error.message }); }
  const ipHash = sha256(`${req.ip}:${process.env.JWT_SECRET}`);
  const { rows } = await pool.query('INSERT INTO submissions(form_id,data,is_spam,source_ip_hash) VALUES($1,$2,$3,$4) RETURNING *', [form.id,JSON.stringify(data),isSpam,ipHash]);
  if (form.webhook_url && !isSpam) await pool.query('INSERT INTO webhook_deliveries(submission_id,webhook_url,payload) VALUES($1,$2,$3)', [rows[0].id,form.webhook_url,JSON.stringify({ form_id:form.id,submission_id:rows[0].id,data,created_at:rows[0].created_at })]);
  if (!isSpam) sendSubmissionEmail(form, rows[0]).catch((error)=>console.error('[Email]',error.message));
  if (req.accepts('html') && form.redirect_url) return res.redirect(303, form.redirect_url);
  res.status(201).json({ ok:true,id:rows[0].id });
});

async function deliverWebhooks() {
  const { rows } = await pool.query(`UPDATE webhook_deliveries SET status='processing' WHERE id IN (SELECT id FROM webhook_deliveries WHERE status='pending' AND next_attempt_at<=NOW() FOR UPDATE SKIP LOCKED LIMIT 20) RETURNING *`);
  for (const delivery of rows) {
    const form = await pool.query('SELECT webhook_secret FROM forms f JOIN submissions s ON s.form_id=f.id WHERE s.id=$1', [delivery.submission_id]);
    try {
      await assertSafeUrl(delivery.webhook_url);
      const body = JSON.stringify(delivery.payload);
      const response = await fetch(delivery.webhook_url, { method:'POST',redirect:'error',headers:{'Content-Type':'application/json','X-FormForge-Signature':signWebhook(form.rows[0].webhook_secret,body)},body,signal:AbortSignal.timeout(10000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      await pool.query("UPDATE webhook_deliveries SET status='delivered',delivered_at=NOW(),attempt=attempt+1 WHERE id=$1",[delivery.id]);
    } catch (error) {
      const final = delivery.attempt >= 4;
      await pool.query("UPDATE webhook_deliveries SET status=$1,attempt=attempt+1,last_error=$2,next_attempt_at=NOW()+make_interval(mins => power(2,attempt)::int) WHERE id=$3",[final?'failed':'pending',error.message,delivery.id]);
    }
  }
}

async function cleanup() {
  await pool.query(`DELETE FROM submissions s USING forms f WHERE s.form_id=f.id AND s.created_at < NOW() - make_interval(days => f.retention_days)`);
}

app.get('/health', (_,res) => res.json({status:'ok'}));
app.use((error,req,res,next) => { console.error(error); res.status(500).json({error:'Server error'}); });

async function start() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32 || process.env.JWT_SECRET.includes('replace_')) throw new Error('Set a secure JWT_SECRET');
  await initDb();
  webhookTimer = setInterval(() => deliverWebhooks().catch(console.error),10000);
  cleanupTimer = setInterval(() => cleanup().catch(console.error),86400000);
  webhookTimer.unref(); cleanupTimer.unref();
  server = app.listen(process.env.PORT || 3002);
}
let server;
let webhookTimer;
let cleanupTimer;
async function shutdown(signal) {
  console.log(`[Shutdown] ${signal} received`);
  if (webhookTimer) clearInterval(webhookTimer);
  if (cleanupTimer) clearInterval(cleanupTimer);
  if (server) await new Promise((resolve) => server.close(resolve));
  await pool.end();
  process.exit(0);
}
process.once('SIGTERM', () => shutdown('SIGTERM').catch((error) => { console.error(error); process.exit(1); }));
process.once('SIGINT', () => shutdown('SIGINT').catch((error) => { console.error(error); process.exit(1); }));
if (require.main === module) start().catch((error) => { console.error(error.message); process.exit(1); });
module.exports = { app, deliverWebhooks, validateSchema, validateSubmission };

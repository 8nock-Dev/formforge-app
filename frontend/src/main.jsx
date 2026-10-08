import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import './style.css';

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3002/api' });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ff_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

const fieldsToSchema = (value) => String(value).split(',').map((item) => item.trim()).filter(Boolean).map((name) => ({
  name, type: name.toLowerCase().includes('email') ? 'email' : 'text', required: false,
}));
const commaList = (value) => String(value).split(',').map((item) => item.trim()).filter(Boolean);

function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [register, setRegister] = useState(false);
  const [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault(); setError('');
    try {
      const response = await api.post(`/auth/${register ? 'register' : 'login'}`, { email, password, name });
      localStorage.setItem('ff_token', response.data.token); onLogin();
    } catch (requestError) { setError(requestError.response?.data?.error || 'Unable to continue'); }
  }
  return <main className="center"><form className="card stack" onSubmit={submit}>
    <h1>FormForge</h1><p>Self-hosted form endpoints with validation and delivery logs.</p>
    {register && <label>Name<input value={name} onChange={(event) => setName(event.target.value)} required /></label>}
    <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
    <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength="8" required /></label>
    {error && <p className="error">{error}</p>}<button>{register ? 'Create account' : 'Sign in'}</button>
    {!register && <a className="auth-link" href="/forgot-password">Forgot password?</a>}
    <button type="button" className="link" onClick={() => { setRegister(!register); setError(''); }}>{register ? 'Use existing account' : 'Create an account'}</button>
  </form></main>;
}

function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { const { data } = await api.post('/auth/forgot-password', { email }); setMessage(data.message); }
    catch (requestError) { setError(requestError.response?.data?.error || 'Unable to request a reset link.'); }
    finally { setBusy(false); }
  }
  return <main className="center"><form className="card stack" onSubmit={submit}>
    <h1>Forgot your password?</h1><p>Enter your account email and we’ll send a secure reset link.</p>
    {message ? <div className="notice">{message}</div> : <><label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required autoComplete="email" /></label>{error && <p className="error">{error}</p>}<button disabled={busy}>{busy ? 'Sending…' : 'Send reset link'}</button></>}
    <a className="auth-link" href="/">Back to sign in</a>
  </form></main>;
}

function ResetPassword() {
  const token = new URLSearchParams(window.location.search).get('token');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setError('');
    if (password !== confirm) return setError('Passwords do not match');
    setBusy(true);
    try { const { data } = await api.post('/auth/reset-password', { token, password }); setMessage(data.message); }
    catch (requestError) { setError(requestError.response?.data?.error || 'Unable to reset password.'); }
    finally { setBusy(false); }
  }
  return <main className="center"><div className="card stack"><h1>Choose a new password</h1><p>Use at least 8 characters.</p>
    {!token ? <p className="error">This reset link is invalid.</p> : message ? <><div className="notice">{message}</div><a className="auth-link" href="/">Continue to sign in</a></> :
      <form className="stack" onSubmit={submit}>{error && <p className="error">{error}</p>}<label>New password<input type="password" minLength="8" required value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></label><label>Confirm new password<input type="password" minLength="8" required value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" /></label><button disabled={busy}>{busy ? 'Resetting…' : 'Reset password'}</button></form>}
  </div></main>;
}

function App() {
  const [logged, setLogged] = useState(Boolean(localStorage.getItem('ff_token')));
  const [forms, setForms] = useState([]);
  const [selected, setSelected] = useState(null);
  const [submissions, setSubmissions] = useState([]);
  const [created, setCreated] = useState(null);
  const [webhookSecret, setWebhookSecret] = useState(null);
  const [error, setError] = useState('');
  async function load() {
    const response = await api.get('/forms'); setForms(response.data);
    if (selected) setSelected(response.data.find((form) => form.id === selected.id) || null);
  }
  useEffect(() => { if (logged) load().catch(() => setLogged(false)); }, [logged]);
  async function create(event) {
    event.preventDefault(); setError(''); const data = new FormData(event.currentTarget);
    try {
      const response = await api.post('/forms', { name: data.get('name'), schema: fieldsToSchema(data.get('fields')), allowed_origins: commaList(data.get('origins')), retention_days: 365 });
      setCreated(response.data); event.currentTarget.reset(); await load();
    } catch (requestError) { setError(requestError.response?.data?.error || 'Unable to create form'); }
  }
  async function open(form) { setSelected(form); const response = await api.get(`/forms/${form.id}/submissions`); setSubmissions(response.data); }
  async function update(event) {
    event.preventDefault(); setError(''); const data = new FormData(event.currentTarget);
    try {
      const response = await api.put(`/forms/${selected.id}`, {
        name: data.get('name'), schema: fieldsToSchema(data.get('fields')), allowed_origins: commaList(data.get('origins')),
        retention_days: Number(data.get('retention_days')), is_active: data.get('is_active') === 'on',
        redirect_url: data.get('redirect_url') || null, notify_email: data.get('notify_email') || null, webhook_url: data.get('webhook_url') || null,
      });
      if (response.data.webhook_secret) setWebhookSecret(response.data.webhook_secret);
      setSelected({ ...selected, ...response.data }); await load();
    } catch (requestError) { setError(requestError.response?.data?.error || 'Unable to save form'); }
  }
  async function rotateToken() {
    if (!window.confirm('Rotate this endpoint token? The previous token will stop working immediately.')) return;
    const response = await api.post(`/forms/${selected.id}/rotate-token`);
    setCreated({ name: selected.name, token: response.data.token, rotated: true }); await load();
  }
  async function exportCsv() {
    const response = await api.get(`/forms/${selected.id}/submissions.csv`, { responseType: 'blob' });
    const url = URL.createObjectURL(response.data); const link = document.createElement('a');
    link.href = url; link.download = `${selected.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-submissions.csv`; link.click(); URL.revokeObjectURL(url);
  }
  async function rotateWebhookSecret() {
    if (!window.confirm('Rotate the webhook signing secret? Receivers using the old secret will stop validating deliveries.')) return;
    try {
      const response = await api.post(`/forms/${selected.id}/rotate-webhook-secret`);
      setWebhookSecret(response.data.webhook_secret);
    } catch (requestError) { setError(requestError.response?.data?.error || 'Unable to rotate webhook secret'); }
  }
  async function deleteSubmission(id) {
    if (!window.confirm('Delete this submission permanently?')) return;
    await api.delete(`/forms/${selected.id}/submissions/${id}`); setSubmissions((current) => current.filter((submission) => submission.id !== id)); await load();
  }
  async function deleteForm() {
    if (!window.confirm(`Delete ${selected.name} and all its submissions permanently?`)) return;
    await api.delete(`/forms/${selected.id}`); setSelected(null); setSubmissions([]); setCreated(null); await load();
  }
  if (!logged) return <Login onLogin={() => setLogged(true)} />;
  return <><header><strong>🔧 FormForge</strong><button className="secondary" onClick={() => { localStorage.removeItem('ff_token'); setLogged(false); }}>Sign out</button></header>
    <main className="layout"><section className="card stack"><h2>Create endpoint</h2><form className="stack" onSubmit={create}>
      <label>Form name<input name="name" required placeholder="Contact form" /></label>
      <label>Fields, separated by commas<input name="fields" required placeholder="name,email,message" /></label>
      <label>Allowed origins, separated by commas<input name="origins" placeholder="https://example.com" /></label><button>Create form</button>
    </form>{error && <p className="error">{error}</p>}{created && <div className="notice"><strong>{created.rotated ? 'Copy the new token now:' : 'Copy this token now:'}</strong><code>{created.token}</code><button type="button" className="compact" onClick={() => navigator.clipboard.writeText(created.token)}>Copy token</button>{!created.rotated && <small>Webhook secret: {created.webhook_secret || 'not configured'}</small>}</div>}</section>
    <section className="card"><h2>Your forms</h2>{forms.length === 0 && <p className="muted">No forms yet.</p>}{forms.map((form) => <button className="row" key={form.id} onClick={() => open(form)}><span>{form.name}<small>{form.token_prefix}… · {form.is_active ? 'Active' : 'Paused'}</small></span><b>{form.submission_count}</b></button>)}</section>
    <section className="card wide"><h2>{selected ? `${selected.name} settings` : 'Select a form'}</h2>{selected && <><form className="settings" key={selected.id} onSubmit={update}>
      <label>Form name<input name="name" defaultValue={selected.name} required /></label><label>Fields, separated by commas<input name="fields" defaultValue={selected.schema.map((field) => field.name).join(',')} required /></label>
      <label>Allowed origins<input name="origins" defaultValue={selected.allowed_origins.join(',')} /></label><label>Retention days<input name="retention_days" type="number" min="1" max="3650" defaultValue={selected.retention_days} required /></label>
      <label>Success redirect URL<input name="redirect_url" type="url" defaultValue={selected.redirect_url || ''} placeholder="https://example.com/thanks" /></label><label>Notification email<input name="notify_email" type="email" defaultValue={selected.notify_email || ''} placeholder="you@example.com" /></label>
      <label className="full">Webhook URL<input name="webhook_url" type="url" defaultValue={selected.webhook_url || ''} placeholder="https://example.com/webhooks/formforge" /></label>
      <label className="checkbox"><input name="is_active" type="checkbox" defaultChecked={selected.is_active} /> Endpoint active</label><div className="actions"><button>Save settings</button><button type="button" className="secondary-action" onClick={rotateToken}>Rotate token</button><button type="button" className="secondary-action" onClick={rotateWebhookSecret} disabled={!selected.webhook_url}>Rotate webhook secret</button><button type="button" className="secondary-action" onClick={exportCsv}>Export CSV</button><button type="button" className="danger" onClick={deleteForm}>Delete form</button></div>
      {webhookSecret && <div className="notice full"><strong>Copy this webhook secret now:</strong><code>{webhookSecret}</code><button type="button" className="compact" onClick={() => navigator.clipboard.writeText(webhookSecret)}>Copy secret</button><small>It will not be shown again.</small></div>}
    </form><h3>Submissions</h3>{submissions.length === 0 && <p className="muted">No submissions yet.</p>}{submissions.map((submission) => <article key={submission.id}><div className="submission-head"><time>{new Date(submission.created_at).toLocaleString()}</time>{submission.is_spam && <span className="badge">Spam</span>}<button className="danger compact" onClick={() => deleteSubmission(submission.id)}>Delete</button></div><pre>{JSON.stringify(submission.data, null, 2)}</pre></article>)}</>}</section></main></>;
}

const path = window.location.pathname;
createRoot(document.getElementById('root')).render(path === '/forgot-password' ? <ForgotPassword /> : path === '/reset-password' ? <ResetPassword /> : <App />);

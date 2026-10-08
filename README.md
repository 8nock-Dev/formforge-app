# FormForge

FormForge is a self-hosted form endpoint service. It accepts JSON or standard HTML form submissions, validates them against a per-form schema, stores them in PostgreSQL, exports safe CSV, and queues signed webhook deliveries.

## Implemented

- JWT-authenticated form dashboard
- Secure email password recovery with hashed, one-time reset tokens
- Unguessable, hashed and rotatable endpoint tokens
- Per-form field schemas and allowed origins
- Honeypot detection and per-IP rate limiting
- Submission inbox and spreadsheet-safe CSV export
- Signed webhook deliveries with persistent retries and delivery status
- Dashboard controls for endpoint settings, pause/resume, token rotation, CSV export and deletion
- One-time webhook signing secrets with explicit secret rotation
- Configurable retention with automatic cleanup
- Private-network URL blocking for redirects and webhooks
- Docker Compose configuration, tests and production frontend build

File uploads are intentionally excluded until object storage, content limits and malware scanning are configured.

## Local development

1. Copy `backend/.env.example` to `backend/.env` and replace `JWT_SECRET`. Keep `DATABASE_SSL=false` for local PostgreSQL; enable it only when your hosted database requires SSL.
2. Start PostgreSQL on port 5436, or use `docker compose up db`.
3. Run `npm install` and `npm run dev` in both `backend/` and `frontend/`.
4. Open `http://localhost:5174`.

## Verify

```bash
npm run test
npm run build
```

## Public submission

See `DEPLOYMENT.md` for production environment variables, Vercel SPA routing, secret handling and database backups.

```html
<form action="https://your-formforge.example/f/FORM_TOKEN" method="POST">
  <input name="name">
  <input name="email" type="email">
  <input name="_honeypot" hidden tabindex="-1">
  <button>Send</button>
</form>
```

Webhook requests include `X-FormForge-Signature`, an HMAC-SHA256 signature of the raw JSON payload.

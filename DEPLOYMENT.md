# Deployment checklist

## Frontend (Vercel)

- Set the project root to `frontend`.
- Build command: `npm run build`; output directory: `dist`.
- Set `VITE_API_URL=https://YOUR_BACKEND_DOMAIN/api`.
- `frontend/vercel.json` preserves the forgot-password and reset-password routes.

## Backend

Run the `backend/Dockerfile` on an always-on container host. Set `PORT`, `DATABASE_URL`, `DATABASE_SSL=true` when PostgreSQL requires TLS, `JWT_SECRET`, `FRONTEND_URL`, `APP_URL`, and SMTP variables. Use the final HTTPS Vercel origin for both URL variables.

The service exposes `GET /health`, handles termination gracefully, and runs webhook delivery and retention workers in-process. Keep one active worker replica unless job claiming is redesigned for multiple replicas.

## Secrets and integrations

Use at least 32 random bytes for `JWT_SECRET`. Never commit `.env`, SMTP credentials, database URLs, form endpoint tokens, reset tokens, or webhook signing secrets. Rotate any token accidentally exposed in logs or screenshots.

## Backups

```bash
pg_dump --format=custom "$DATABASE_URL" > formforge-$(date +%F).dump
pg_restore --clean --if-exists --dbname="$RESTORE_DATABASE_URL" formforge-YYYY-MM-DD.dump
```

Schedule encrypted daily backups, retain at least seven, and test restoration before launch.

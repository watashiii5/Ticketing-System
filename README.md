# Ticketing System
Modern service desk for internal IT teams, built with Node.js + Express and deployed on Render.
ticketing-system-8yho.onrender.com/
## Highlights
- Branded company portals with invite-only or domain-restricted access
- AI-style priority hints, SLA due dates, and real-time status updates
- Attachment uploads and inline comments per ticket
- Multi-tenant companies with plan limits, billing, and audit logs
- Super admin dashboard for platform oversight

## Tech Stack
- Node.js + Express (server-rendered HTML)
- Postgres (Render managed database)
- Session-based auth + bcrypt
- Multer for attachments

## Local Development
1. Install dependencies
   - `npm install`
2. Configure environment
   - `DATABASE_URL=postgres://...`
   - `SESSION_SECRET=your-secret`
3. Start the server
   - `npm run dev`
4. Open `http://localhost:3000`

## Default Logins (seeded)
Use these after the first local boot:
- Platform admin: `admin@platform.test` / `password123`
- Sample users: `avery.kim@acme.test` / `password123`

## Environment Variables
- `DATABASE_URL` (required)
- `SESSION_SECRET` (required)
- `UPLOADS_DIR` (optional, defaults to `uploads/`)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` (optional for email)
- `NOTIFY_TO`, `NOTIFY_FROM` (optional for notifications)

## Render Deployment
This repo includes a `render.yaml` for one-click deploys.

1. Create a new Web Service on Render
2. Add a Postgres database and copy its `DATABASE_URL`
3. Set environment variables
   - `DATABASE_URL`
   - `SESSION_SECRET`
   - `UPLOADS_DIR=/opt/render/project/src/uploads`
4. Deploy

The app auto-initializes the database schema on boot.

## Data & Files
- Uploaded files are stored on disk under `uploads/` (or `UPLOADS_DIR`)
- The database uses Postgres via `DATABASE_URL`

## Scripts
- `npm run dev` - start the app

## License
ISC

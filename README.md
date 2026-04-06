# FileCloud Enterprise – Everfox CDR + ClamAV + ICAP

Production-ready file security pipeline with real ClamAV, S3, PostgreSQL, Celery, RBAC, rate limiting, WebSockets, and modern UI.

## Quick Start

1. Copy `.env.example` to `.env` and fill in your values.
2. Generate self-signed certificates: `cd certs && chmod +x generate.sh && ./generate.sh`
3. Start all services: `docker-compose -f docker-compose.prod.yml up --build`
4. Access the UI at `https://localhost` (ignore browser warning).

## Features

- ✅ Real ClamAV antivirus scanning
- ✅ Asynchronous CDR with Celery + Redis
- ✅ S3 storage for original and sanitized files
- ✅ JWT authentication + role-based access (admin/user)
- ✅ Rate limiting per endpoint
- ✅ Full audit logs + webhook forwarding
- ✅ WebSocket live updates
- ✅ Modern responsive dashboard (dark/light mode)
- ✅ File preview (images, PDFs)
- ✅ Drag & drop folder upload
- ✅ Prometheus metrics
- ✅ API keys for automation
- ✅ User quotas & workspaces
- ✅ Expiring share links

## API Endpoints

- `POST /api/register` – create account (pending approval)
- `POST /api/login` – get JWT token
- `POST /api/upload/batch` – upload multiple files
- `GET /api/status/{file_id}` – check processing status
- `GET /api/download/{file_id}` – download sanitized file
- `GET /api/share/{file_id}` – create expiring share link
- `GET /api/audit` – (admin) view audit logs
- `GET /metrics` – Prometheus metrics

## License

MIT

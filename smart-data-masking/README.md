# Smart Data Masking System

A Python system for finding potentially sensitive database columns and applying stored masking policies before any API response returns records. It combines a SQLAlchemy scanner and adapters, persisted classifications and policies, FastAPI authentication and authorization, and a Streamlit dashboard. Local development uses synthetic SQLite data; PostgreSQL is supported as an optional configured source.

## Architecture

```mermaid
flowchart LR
    UI[Streamlit dashboard] -->|Bearer token| API[FastAPI]
    CLI[Local CLI] --> CTRL[(Control database)]
    API --> AUTH[Authentication and permission checks]
    AUTH --> CTRL
    API --> REG[Configured database registry]
    REG --> SQLITE[Read-only SQLite adapter]
    REG --> PG[Read-only PostgreSQL adapter]
    SQLITE --> SCAN[Scanner]
    PG --> SCAN
    SCAN --> META[Classifications]
    API --> QUERY[Controlled QueryService]
    QUERY --> POLICY[Policy evaluation]
    QUERY --> MASK[Masking engine]
    QUERY --> AUDIT[Privacy-conscious audit]
    META --> CTRL
    POLICY --> CTRL
    AUDIT --> CTRL
```

The process is: **scan** samples a bounded set of values; **classification** stores labels and confidence; **policy evaluation** checks the persisted role and field rule; **masking** transforms the selected values in the response. The source rows remain unchanged. The dashboard has no direct database connection and does not implement its own masking logic.

The registry exposes server-configured database IDs, never connection URLs. The records endpoint validates selected table and column names against reflected schema and uses SQLAlchemy expressions; it does not accept SQL. SQLite and PostgreSQL adapters are read-only for application access.

## Install and configuration

Python 3.11 or newer is required. From the project folder in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

The application reads process environment variables directly; it does not automatically load `.env`. Use [.env.example](.env.example) as a reference and export values in the shell, service manager, or secrets manager. The dashboard uses `SMARTMASK_API_BASE_URL`, defaulting to `http://127.0.0.1:8000/api/v1`.

Before starting the API, set `SMARTMASK_JWT_SECRET` to at least 32 random bytes. Generate one with:

```powershell
$env:SMARTMASK_JWT_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(48))")
```

If Analyst pseudonyms are needed, set an independent `SMARTMASK_HMAC_SECRET`. Never commit actual secrets. The API binds to `127.0.0.1` by default; configure exact CORS origins and trusted hosts for a deployment. API docs default off when `SMARTMASK_ENVIRONMENT=production`, unless explicitly enabled. Responses use `Cache-Control: no-store`.

## Initialize synthetic SQLite data

```powershell
smartmask init
smartmask seed-demo
smartmask scan
smartmask classifications
smartmask seed-policies
smartmask demo --role Support --limit 2
smartmask demo --role Analyst --limit 2
```

The demo contains fictional customer rows and `.test` email addresses. Seeding is repeatable and does not replace existing rows. `smartmask init` applies additive, idempotent control-schema upgrades; back up the control database before upgrading an installation. The explicit `data/setup_demo.py --drop` option is destructive to the demo `customers` table and is not needed for the normal workflow.

## Authentication, roles, and permissions

Create users from a trusted local shell. The CLI requests passwords through a hidden prompt; passwords are stored using Argon2id. No default demo users or passwords are seeded.

```powershell
smartmask users create alice --role Support
smartmask users grant alice data:read
smartmask users grant alice database:select
smartmask users grant alice scan:read
smartmask users list

# To use protected user/policy administration in the dashboard:
smartmask users create operator --role Admin
smartmask users grant operator users:manage
smartmask users grant operator policy:read
smartmask users grant operator policy:write
smartmask users grant operator audit:read
smartmask users grant operator database:select
smartmask users grant operator scan:run
smartmask users grant operator scan:read
smartmask users grant operator scan:review
```

Permissions are explicit: `data:read`, `data:read_raw`, `database:select`, `scan:run`, `scan:read`, `scan:review`, `policy:read`, `policy:write`, `audit:read`, and `users:manage`. Role names do not imply permissions. An Admin needs `data:read_raw` as well as a matching stored `allow` policy before raw sensitive values can be returned. Without it, sensitive `allow` decisions are reduced to a safe mask. Grant only the permissions a user needs.

JWTs are signed HS256 tokens with issuer, audience, expiry, unique token ID, subject, and user token version. The API resolves the current role and grants from the control store on each request. Grant/revoke changes therefore apply immediately; role, password, account deactivation, and logout changes revoke existing tokens as documented by the account service. Failed logins use generic responses, persistent lockout, and an in-process IP limiter. Use shared edge rate limiting for multi-worker deployments.

## Start the API and dashboard

Start the backend in one terminal after initialization and user provisioning:

```powershell
smartmask-api
```

Start the dashboard in a second terminal from the project root:

```powershell
streamlit run dashboard.py
```

Open the Streamlit URL printed by the command (normally `http://localhost:8501`). The login form calls the real `/auth/token` endpoint. The bearer token lives in server-side Streamlit session state only; logout clears it. The dashboard does not persist passwords or protected records in browser storage or a persistent cache. Expired/invalid sessions return to login.

The UI includes:

- **Overview:** live registry, table, classification, policy, and recent audit counts only when the current identity can access those endpoints.
- **Connections:** lists configured IDs and tests source reachability through table discovery. It never accepts arbitrary URLs.
- **PII scanner:** starts authorized scans, shows actual classifications/reasons/confidence, and supports authorized review.
- **Masked-data explorer:** allows table and column selection, then calls the controlled records route. The backend transforms values before returning them.
- **Policies:** displays stored policies and offers validated edits only to `policy:write` users.
- **Users and permissions:** calls server-protected user administration endpoints only for `users:manage`. Administrators cannot change their own role or permissions through these routes; role updates revoke that user’s tokens.
- **Audit viewer:** displays read-only events only to `audit:read` users, with a search filter over the requested page and bounded pagination.
- **API status:** distinguishes dashboard, API, control-store, and selected source-connection status.

The UI hides unavailable controls for usability, but the API independently checks every sensitive action. API errors shown by the UI are sanitized; denied protected results are not displayed.

## API route summary

Routes are under `/api/v1`. Apart from health, readiness, and login, they require a bearer token and permission.

| Route | Required permission | Purpose |
|---|---|---|
| `GET /health` | none | Process liveness |
| `GET /ready` | none | Control-store readiness |
| `POST /auth/token`, `GET /auth/me`, `POST /auth/logout` | public / authenticated | Login, current identity, token revocation |
| `GET /databases` | `database:select` | Configured connection IDs and backend labels |
| `GET /databases/{id}/tables` | `database:select` | Table discovery and source reachability |
| `GET /databases/{id}/tables/{table}/columns` | `database:select` | Reflected column names/types |
| `POST /databases/{id}/scans` | `scan:run` + `database:select` | Bounded schema/sample scan |
| `GET /scans/{id}` | `scan:read` | Scan status |
| `GET /databases/{id}/classifications` | `scan:read` + `database:select` | Paginated classifications |
| `PATCH /classifications/{id}/review` | `scan:review` | Classification review |
| `GET /databases/{id}/tables/{table}/records` | `data:read` + `database:select` | Policy-controlled rows; repeated `columns` query parameters are validated |
| `GET /policies`, `POST /policies`, `PATCH /policies/{id}` | `policy:read` / `policy:write` | Inspect and edit policies |
| `GET /users`, `GET /permissions` | `users:manage` | Inspect accounts and permission vocabulary |
| `PATCH /users/{id}/role` | `users:manage` | Change role and revoke existing tokens |
| `PUT/DELETE /users/{id}/permissions` | `users:manage` | Grant/revoke permission |
| `GET /audit-events` | `audit:read` | Bounded audit-event pagination |

No route allows arbitrary SQL or client-supplied database URLs, roles, or user identities. The client cannot request raw values by changing a query parameter; raw access needs a persisted grant and an applicable stored policy.

## PostgreSQL

Set `SMARTMASK_POSTGRES_DB_URL` to a `postgresql+psycopg://` URL and `SMARTMASK_POSTGRES_SCHEMA` to the source schema. The configured `postgresql_demo` registry entry is then available. Use a dedicated least-privileged reader role; [data/postgres_reader.sql](data/postgres_reader.sql) is a starting point. Do not put production passwords in that file. PostgreSQL runtime integration was not available in the audit environment.

The optional test creates and drops a uniquely named schema, so point it only at a **disposable** database and use an account allowed to create/drop schemas. With Docker installed:

```powershell
docker run --rm --name smartmask-pg-audit -e POSTGRES_PASSWORD=local-only-test-password -e POSTGRES_DB=smartmask_test -p 5432:5432 -d postgres:16
$env:SMARTMASK_TEST_POSTGRES_URL = 'postgresql+psycopg://postgres:local-only-test-password@127.0.0.1:5432/smartmask_test'
python -m pytest -q -m postgres
docker stop smartmask-pg-audit
```

## Tests and repeatable synthetic verification

```powershell
python -m pytest -q -ra
python -m pytest -q tests/test_end_to_end.py
```

The end-to-end test seeds a temporary synthetic SQLite source, scans it, provisions a limited Support account through the CLI provisioning function, logs in through the API, checks protected column-selected output and denial, inspects audit records, and compares a source-row digest before/after. Tests use isolated temporary databases; they do not alter the project’s existing SQLite database files.

## Security and operational limitations

- PostgreSQL support is implemented, but live integration must still be run in an environment with a disposable PostgreSQL service.
- API user administration is permission-protected; CLI access remains a trusted-host administrative capability.
- The control database contains accounts, grants, policies, and audit data; restrict filesystem and database access and back it up securely.
- TLS, secret rotation/storage, backups, monitoring, process supervision, shared rate limiting, and deployment-specific CORS/trusted-host allowlists are operational requirements.
- Sampling may miss PII. Review uncertain classifications before broad access grants.
- HMAC output is deterministic keyed pseudonymization, not encryption or anonymization. Protect the key.
- This project makes no regulatory compliance claim and is not presented as production-ready.


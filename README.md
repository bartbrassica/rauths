# rauths

A headless central authentication microservice built in Rust. Designed as the single source of truth for identity across multiple services — exposes a public REST API for clients and a private gRPC interface for internal service-to-service token verification.

## Features

- Email/password registration and login with Argon2id hashing
- Short-lived Ed25519-signed access tokens + Redis-backed, revocable refresh tokens
- OAuth2 login via GitHub and Google (with PKCE)
- Email verification and password reset flows (delivered via Resend)
- Role-based access control
- Per-IP rate limiting on auth endpoints and per-user rate limiting on authenticated endpoints
- Audit logging of security-relevant events (logins, lockouts, password resets, OAuth linking, ...)
- Prometheus metrics (`/metrics`) and OpenAPI documentation (`/docs`, `/openapi.yaml`)

## Tech Stack

| Concern | Crate / Tool |
|---|---|
| Web framework | `axum` 0.8 |
| Internal RPC | `tonic` (gRPC) |
| Database | PostgreSQL 17 via `sqlx` (compile-time queries) |
| Cache / session state | Redis 7 |
| Password hashing | `argon2` (Argon2id) |
| JWT signing | `jsonwebtoken` + Ed25519 (EdDSA) |
| Email delivery | Resend |
| Metrics | `axum-prometheus` |
| Async runtime | `tokio` |

## Architecture

```
             ┌─────────────────────────────────────┐
             │              rauths                │
             │                                     │
Clients ────►│  Axum REST  :3000                   │
             │  /register  /login  /refresh         │
             │  /logout  /me  /password-reset/*     │
             │  /email-verify/*  /auth/{provider}   │
             │                                     │
Services ───►│  Tonic gRPC :50051                  │
             │  AuthService.VerifyToken             │
             │                                     │
             └────────┬──────────────┬─────────────┘
                      │              │
                 PostgreSQL        Redis
                 (users, roles,    (refresh tokens /
                  audit events,     session revocation /
                  oauth links, ...) rate-limit counters)
```

**Token strategy:** short-lived access tokens (15 min) + long-lived refresh tokens (7 days) stored in Redis. Ed25519 signatures — no symmetric secrets shared with downstream services.

## Project Structure

```
.
├── proto/          # Protobuf definitions
├── migrations/     # SQLx migrations
├── tests/          # Integration tests (full HTTP round-trips)
└── src/
    ├── main.rs     # Server bootstrap (Axum + Tonic)
    ├── lib.rs      # Router assembly (public + production routers)
    ├── routes/     # REST handlers (public API, incl. OAuth)
    ├── services/   # gRPC implementations (internal API)
    ├── domain/     # Business logic (hashing, JWT)
    ├── data/       # Repository layer (SQLx queries)
    ├── email.rs    # Transactional email client (Resend)
    └── middleware/ # Auth guards, rate limiting
```

## Getting Started

### Prerequisites

- Rust (stable)
- Docker & Docker Compose
- [Task](https://taskfile.dev) (`brew install go-task` / `cargo install go-task`)
- `protoc` + `sqlx-cli` (installed via `task setup`)

### First-time setup

```bash
git clone https://github.com/bartbrassica/rauths
cd rauths
task setup          # copies .env, installs tooling
task keys:gen       # generates Ed25519 keypair → private.pem + public.pem
```

Paste the contents of `private.pem` and `public.pem` into `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` in `.env`.

### Run in development

```bash
task infra:up       # start Postgres + Redis
task db:migrate     # apply migrations
task dev            # run with auto-reload (cargo-watch)
```

### Run tests

```bash
task infra:up
task test
```

Integration tests spin up the full Axum router. Database tests use `#[sqlx::test]` — each test gets its own isolated throwaway database, no shared state.

## REST API

| Endpoint | Description |
|---|---|
| `POST /register` | Create an account |
| `POST /login` | Exchange credentials for an access + refresh token |
| `POST /refresh` | Exchange a refresh token for a new access token |
| `POST /logout` | Revoke the current refresh token |
| `POST /me/sessions/revoke-all` | Revoke all of the user's refresh tokens |
| `GET /me` / `DELETE /me` | Fetch or delete the current user |
| `PATCH /me/password` | Change the current user's password |
| `POST /password-reset/request` / `POST /password-reset/confirm` | Password reset flow (email-based) |
| `POST /email-verify/request` / `POST /email-verify/confirm` | Email verification flow |
| `GET /auth/{provider}` / `GET /auth/{provider}/callback` | OAuth2 login via `github` or `google` |
| `GET /health` | Liveness check |
| `GET /metrics` | Prometheus metrics |
| `GET /docs` / `GET /openapi.yaml` | OpenAPI documentation |

The production router (`build_production_router`) additionally applies per-IP rate limiting to `/login`, `/register`, `/password-reset/request`, and `/email-verify/request`, and per-user rate limiting to authenticated endpoints (`/logout`, `/me`, `/me/password`, `/me/sessions/revoke-all`).

## Configuration

Copy `.env.example` to `.env` and fill in the values:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |
| `JWT_PRIVATE_KEY_PEM` | Ed25519 private key (PEM) |
| `JWT_PUBLIC_KEY_PEM` | Ed25519 public key (PEM) |
| `ACCESS_TOKEN_EXPIRY_SECONDS` | Access token TTL (default: 900) |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | Refresh token TTL (default: 604800) |
| `RESEND_API_KEY` | API key for the Resend transactional email service |
| `RESEND_FROM_EMAIL` | "From" address for verification/reset emails |
| `APP_BASE_URL` | Public base URL used to build links in emails and OAuth callbacks |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth2 app credentials (optional — enables `/auth/github`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth2 app credentials (optional — enables `/auth/google`) |
| `HTTP_ADDR` | Axum listen address (default: `0.0.0.0:3000`) |
| `GRPC_ADDR` | Tonic listen address (default: `0.0.0.0:50051`) |
| `LOG_FORMAT` | Set to `json` for structured JSON logs (default: plain text) |

## Production Deployment

```bash
task docker:up      # build image + start full stack (app + infra)
task docker:logs    # stream app logs
task docker:down    # stop everything
```

## Common Tasks

```
task              # list all tasks
task ci           # fmt check + clippy + tests (mirrors CI)
task lint         # clippy with warnings as errors
task db:add -- <name>   # create a new migration
task db:prepare   # regenerate .sqlx offline query cache
```

## gRPC API

Internal services verify tokens via `AuthService.VerifyToken`:

```protobuf
service AuthService {
  rpc VerifyToken (VerifyTokenRequest) returns (VerifyTokenResponse);
}
```

Response includes `valid`, `user_id`, `email`, and `roles` — downstream services need only the public key to independently verify the signature without calling this service.

## License

MIT — see [LICENSE](LICENSE).

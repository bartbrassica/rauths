# rauths

A headless central authentication microservice built in Rust. Designed as the single source of truth for identity across multiple services — exposes a public REST API for clients and a private gRPC interface for internal service-to-service token verification.

## Tech Stack

| Concern | Crate / Tool |
|---|---|
| Web framework | `axum` 0.8 |
| Internal RPC | `tonic` (gRPC) |
| Database | PostgreSQL 17 via `sqlx` (compile-time queries) |
| Cache / session state | Redis 7 |
| Password hashing | `argon2` (Argon2id) |
| JWT signing | `jsonwebtoken` + Ed25519 (EdDSA) |
| Async runtime | `tokio` |

## Architecture

```
             ┌─────────────────────────────────────┐
             │              rauths                │
             │                                     │
Clients ────►│  Axum REST  :3000                   │
             │  /register  /login  /refresh         │
             │  /logout                             │
             │                                     │
Services ───►│  Tonic gRPC :50051                  │
             │  AuthService.VerifyToken             │
             │                                     │
             └────────┬──────────────┬─────────────┘
                      │              │
                 PostgreSQL        Redis
                 (users table)    (refresh tokens /
                                   session revocation)
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
    ├── routes/     # REST handlers (public API)
    ├── services/   # gRPC implementations (internal API)
    ├── domain/     # Business logic (hashing, JWT)
    ├── data/       # Repository layer (SQLx queries)
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
| `HTTP_ADDR` | Axum listen address (default: `0.0.0.0:3000`) |
| `GRPC_ADDR` | Tonic listen address (default: `0.0.0.0:50051`) |

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

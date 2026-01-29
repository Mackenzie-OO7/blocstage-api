# BlocStage API: Decentralized ticketing and event platform

BlocStage API provides a modern server backend for decentralized ticketing, event management and on-chain rewards on Stellar. It blends battle-tested patterns with onchain primitives to make building and running ticketing platforms fast, secure, and scalable.

**Key highlights**:
- Built in Rust
- Actix-web powers a fast, resilient HTTP API surface
- Soroban/Horizon for wallet, USDC onboarding and sponsored payments
- Postgres via sqlx for robust, typed DB access and migrations
- Redis for caching, sessions, rate limiting and analytics
- Shuttle-ready for cloud deployment
- Clean layered, modular architecture (controllers → services → models) that is easy to extend

---

## Table of contents
  - [Goals & overview](#goals--overview)
  - [Architecture](#architecture)
  - [Tech Stack](#tech-stack)
  - [Quick start](#quick-start)
    - [**Requirements**](#requirements)
    - [**Environment**](#environment)
    - [**Run locally**](#run-locally)
  - [Database & migrations](#database--migrations)
  - [Tests](#tests)
  - [Deployment notes (Shuttle)](#deployment-notes-shuttle)
  - [Contributing](#contributing)

---

## Goals & overview
BlocStage's server component focuses on delivering an API for event creators and organisers with blockchain capabilities:

- Ticket lifecycle: create events → create ticket types → purchase → check-in → refunds
- Wallet & payment orchestration on Stellar (USDC, sponsored transactions)
- Admin controls for events & sponsor accounts
- PDF ticket generation, storage upload (Supabase compatible), and email delivery (SendGrid templates)
- Analytics + caching using Redis
- Secure authentication (JWT), password handling (bcrypt), and session management

The server is intentionally modular: lightweight controllers handle HTTP concerns while services encapsulate business logic and integrations.

---

## Architecture

1) HTTP Layer (actix-web)
	- Controllers expose REST endpoints (/auth, /events, /tickets, /transactions, /admin, /health, ...)

2) Service Layer
	- Payment orchestration (StellarService, PaymentOrchestrator, SponsorManager, FeeCalculator)
	- Auth & crypto helpers (jsonwebtoken, bcrypt, KeyEncryption)
	- PDF generation, storage & email (Ticket PDF + SendGrid templating)
	- Redis caching and session management

3) Persistence
	- Postgres via sqlx + robust migrations (migrations/ folder)

4) Integrations & Observability
	- Stellar (Horizon & Soroban client libraries) for on-chain operations
	- Redis (deadpool, connection manager) for caching and rate limits
	- SendGrid templates for reliable email delivery
	- Storage via Supabase-compatible API for serving PDFs
	- Prometheus + OpenTelemetry instrumentation for metrics and tracing

---

## Tech Stack

- Rust: all core code (controllers, services, models and tests) is implemented in `src/`.
- Actix-web: HTTP server, routing and middleware live in `src/main.rs` and `src/controllers/` (handles endpoints, CORS, error handling, and request parsing).
- SQLx + Postgres: DB access implemented in `src/models/` and `src/services/`, schema managed by `migrations/` and sqlx provides typed queries and pooling.
- Shuttle: deployment and runtime configuration via `Shuttle.toml` and the `#[shuttle_runtime::main]` entrypoint in `src/main.rs` (secrets injection and hosting).
- Redis: caching, session management, rate limiting and analytics code is in `src/services/redis_service.rs` and referenced across services.
- Stellar / Soroban: on-chain orchestration (trustlines, USDC ops, transaction submission, sponsored payments) implemented in `src/services/stellar.rs`.
- SendGrid + Storage (Supabase-compatible): email templates and provider implementations in `src/services/email/` and storage upload/signed URLs in `src/services/storage.rs` (ticket PDFs).
- Tracing + OpenTelemetry + Prometheus: observability & metrics integration wired across `src/` using tracing, tracing-opentelemetry and prometheus crates.

---

## Quick start

### **Requirements**
- Rust 1.89+ + cargo
- Postgres (local or remote)
- Optional: Redis (local or remote) and a Supabase-like storage for PDFs

Recommended: use Docker for local Postgres and Redis, or point the env vars to your dev VMs.

### **Environment**
- Copy or create `.env` for local development. The server expects a number of configuration keys — here are the most important:

```env
DATABASE_URL=postgres://user:password@localhost:5432/blocstage
APP_ENV=development
JWT_SECRET=replace_with_a_secure_random_value
EMAIL_FROM=no-reply@blocstage.com
APP_URL=http://localhost:8080
STELLAR_NETWORK=testnet
TESTNET_USDC_ISSUER=G... (Test USDC issuer)
REDIS_URL=redis://127.0.0.1:6379
PLATFORM_PAYMENT_PUBLIC_KEY=G... (platform wallet public key)
SENDGRID_API_KEY=SG.xxxx
STORAGE_URL=https://your-supabase-instance
STORAGE_SERVICE_KEY=service-role-key
STORAGE_BUCKET=ticket-pdfs
```

### **Run locally**

```bash
# install dependencies and build
cargo build --release

# set up your DB and run migrations
export DATABASE_URL=postgres://...
cargo sqlx prepare # if using checked queries
cargo test # run integration tests (reads migrations/ as well)

# Run the web server (Shuttle uses entrypoint annotations)
cargo run
```

**Health endpoint /debug**
- The server exposes `/health` which will check DB, Redis, and email provider health for quick diagnostics.

---

## Database & migrations

- The `migrations/` folder contains SQL migration files tracked by sqlx. Routine commands:

```bash
sqlx migrate run # ensure DATABASE_URL is set
sqlx migrate revert
```

The project uses Postgres as the primary data store and relies on typed SQLx queries for compile-time safety.

---

## Tests

- Integration tests are present in `tests/integration.rs` and exercise the full HTTP stack and many business flows.
- Use a test Postgres instance for the test environment and the `TEST_DATABASE_URL` env var to point tests at an ephemeral DB.

```bash
export TEST_DATABASE_URL=postgres://...
cargo test -- --nocapture
```

---

## Deployment notes (Shuttle)

- This project is configured for Shuttle and exposes a `#[shuttle_runtime::main]` entrypoint (see `src/main.rs`). Shuttle secret injection is used to load production credentials like `DATABASE_URL`, `SENDGRID_API_KEY`, and Stellar keys.
- Ensure required secrets are added into your Shuttle app before release.

---

## Contributing

All contributions are welcome. A few tips:
- Follow Rust idioms and keep unsafe code to a minimum.
- Prefer unit-tested, small, focused PRs.
- Use integration tests where side-effects (DB, external APIs) are required.

---


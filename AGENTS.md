# AGENTS.md

## Project overview
This repository is a Go identity microservice with two interfaces:
- HTTP API via Gin in [internal/transport/http/routes.go](internal/transport/http/routes.go)
- gRPC service entry points registered in [main.go](main.go)

The app persists user data in PostgreSQL, uses Redis for token/session state, and wires all dependencies in [main.go](main.go). Core storage and configuration are under [internal/store](internal/store), while service logic is under [internal/service](internal/service).

## Key commands
- Run the repo test suite: `go test ./...`
- Run only unit tests: `go test ./tests/unit/...`
- Run only integration tests: `go test ./tests/integration/...`
- Start the Docker-based integration environment defined in [docker/docker-compose-test.yml](docker/docker-compose-test.yml): `docker compose -f docker/docker-compose-test.yml up -d`

The integration tests expect the service to be reachable at `http://localhost:8081/api` and rely on the postgres/redis containers declared in [docker/docker-compose-test.yml](docker/docker-compose-test.yml).

## Architecture conventions
- Keep HTTP handlers thin and focused on request/response translation; they should not contain persistence logic.
- Put business logic in the service layer under [internal/service](internal/service).
- Repository access and DB setup belong under [internal/store](internal/store), especially [internal/store/database.go](internal/store/database.go) and [internal/store/identity.go](internal/store/identity.go).
- Token lifecycle and JWT handling belong under [internal/tokens](internal/tokens) and the Redis integration in [internal/store/redis.go](internal/store/redis.go).
- Route-level auth and request validation should follow the existing Gin middleware pattern in [internal/transport/http/middleware](internal/transport/http/middleware).

## Environment and config
- The app loads `.env` at startup if present, as seen in [main.go](main.go).
- Required environment variables include `APP_PORT`, `GRPC_PORT`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_SECRET`, `DB_NAME`, `DB_SSLMODE`, `REDIS_HOST`, `REDIS_PORT`, `ACCESS_SECRET`, and `REFRESH_SECRET`.
- Connection strings are assembled in [internal/store/database.go](internal/store/database.go) using the existing PostgreSQL naming scheme.

## Testing conventions
- Unit tests live under [tests/unit](tests/unit) and use mocks under [tests/mocks](tests/mocks).
- Integration tests live under [tests/integration](tests/integration) and validate the running HTTP API.
- Prefer existing test helpers and real behavior over mock-heavy assertions; do not add test-only production methods.
- When changing API behavior, update the matching unit or integration tests in the corresponding package rather than only patching implementation code.

## Common pitfalls
- `go test ./...` runs integration tests that expect Docker infrastructure to be up.
- Route and middleware behavior are intentionally split between public and protected routes in [internal/transport/http/routes.go](internal/transport/http/routes.go).
- JWT refresh/logout logic uses the expected auth headers and token manager flows; do not introduce alternate conventions without updating the middleware/service contract.
- The project uses domain-style error handling and business validation; preserve the existing error mapping pattern in [internal/transport/http/errorMapper.go](internal/transport/http/errorMapper.go) rather than introducing ad hoc status handling.

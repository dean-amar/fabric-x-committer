# TLS-Enabled PostgreSQL with Docker: Manual Setup

This guide describes how to manually run a PostgreSQL Docker container with **server-side TLS** enabled using custom certificates. It explains the reason for each step and covers important nuances like manual initialization, certificate permissions, and `pg_hba.conf` configuration.

---

## 🌟 Overview

* **Goal:** Secure a PostgreSQL container with TLS using custom certificates
* **Approach:** Manually initialize and configure Postgres to give full control over TLS and users
* **Use case:** Testing with gRPC/TLS services and `pgx` clients requiring strict certificate verification

---

## ✅ What This Script Does

1. Pulls the `postgres:16.9-alpine3.21` image
2. Deletes old container and data directory if they exist
3. Runs `initdb` manually to initialize the database cluster
4. Modifies `pg_hba.conf` to allow encrypted access
5. Secures `server.key` permissions (PostgreSQL requires `0600`)
6. Starts the container with `ssl=on`, using mounted TLS certs
7. Waits for the DB to come up and creates the `yugabyte` database manually

---

## ⚡ Why We Must Start and Restart the Container

We cannot do everything in one `docker run` command because:

| Step                          | Reason                                                             |
| ----------------------------- | ------------------------------------------------------------------ |
| `initdb` with TLS enabled     | ❌ Fails if certs are missing or unconfigured                       |
| Entrypoint auto-init disabled | ✅ We want full manual control over users, trust, TLS               |
| TLS config needs pg\_hba.conf | ✅ `pg_hba.conf` must allow `hostssl` before Postgres starts in TLS |

So we split it into two phases:

1. **Phase 1 - Manual Init:**

    * Use `docker run --rm` to run `initdb` as the `postgres` user
    * Append `hostssl all all all trust` to `pg_hba.conf`
    * Secure cert permissions

2. **Phase 2 - TLS Startup:**

    * Start the actual container with TLS certs and `ssl=on`
    * Use `createdb -U yugabyte yugabyte` to create the database manually

---

## ⚙ Configuration

* **CERTS\_DIR**: Directory containing `server.key`, `server.crt`, and `ca.crt`
* **PGDATA\_DIR**: Temporary path to store Postgres data files
* **Container Name**: `sc_postgres_unit_tests_tls`

---

## 💪 TLS Certificate Requirements

| File         | Required Permissions           | Mounted Path in Container |
| ------------ | ------------------------------ | ------------------------- |
| `server.key` | `600` (readable only by owner) | `/certs/server.key`       |
| `server.crt` | Readable                       | `/certs/server.crt`       |
| `ca.crt`     | Readable                       | `/certs/ca.crt`           |

---

## 🎓 Connection String (for `pgx`, Go, etc.)

```bash
postgres://yugabyte:yugabyte@localhost:5433/postgres?sslmode=verify-ca
```

### Go Example (with `pgx`):

```go
conf, _ := pgx.ParseConfig("postgres://yugabyte:yugabyte@localhost:5433/postgres")
ca, _ := os.ReadFile("/path/to/ca.crt")
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(ca)
conf.TLSConfig = &tls.Config{RootCAs: pool}
conn, _ := pgx.ConnectConfig(context.Background(), conf)
```

---

## 🚀 Final Script Behavior

* Manual `initdb` run with `-U yugabyte`
* `pg_hba.conf` explicitly set to allow encrypted trust-based access
* Postgres starts with full TLS and strict permission compliance
* TLS-enabled clients (e.g. `pgx`) can connect securely with `sslmode=verify-ca`

---

Let me know if you want a Makefile or Docker Compose alternative!

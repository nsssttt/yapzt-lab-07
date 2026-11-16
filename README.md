# Lab 7 Task Board

A small task management app used for the Lab 7 testing exercises. It runs on Python's standard library with SQLite and is packaged for Docker Compose.

## Run locally

Requirements: Docker Desktop with Docker Compose.

```sh
docker compose up --build --detach
```

Open <http://127.0.0.1:8787>. The service binds to loopback by default.

On first launch, create an administrator from the setup page. Retrieve the one-time setup token from the container with:

```sh
docker compose exec taskboard sh -c 'cat /data/bootstrap-token'
```

The token is generated at startup, stored in the local data volume, and removed after administrator setup. Choose a new local email address and password. Do not commit credentials or application data.

Stop the app with:

```sh
docker compose down
```

The `taskboard_data` volume stores the SQLite database. To remove that volume and all local app data, run `docker compose down --volumes`.

## Features

- User registration, sign-in, account roles, and administrator controls
- Task creation, assignment, status updates, editing, soft deletion, and restoration
- Task comments and an activity log
- Password reset links written to a local outbox file
- JSON endpoints at `/api/tasks` and `/api/tasks/{id}` for signed-in users
- Health check at `/health`

Task statuses are `To Do`, `In Progress`, and `Done`. Passwords are stored as salted PBKDF2 hashes. Mutating forms require a CSRF token.

## Configuration

Compose defines the defaults. The container accepts `APP_HOST`, `APP_PORT`, and `APP_DB` environment variables. The default database path is `/data/taskboard.sqlite3`.

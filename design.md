# Design Document

## System Overview

```
+-------------+         HTTP          +-------------+
|             |  ------------------>  |             |
| simulator   |  /login, /register    |   server    |
|   (CLI)     |  <------------------  |  (FastAPI)  |
|             |    JSON response      |             |
+-------------+                       +-------------+
                                            |
                                            | writes
                                            v
                                      +-------------+
                                      | attempts_   |
                                      | <hash>_     |
                                      | <defenses>_ |
                                      | <attack>.log|
                                      +-------------+
```

**Components:**
- **server.py** - Authentication server (FastAPI)
- **setup_db.py** - Script for resetting DB tables and seeding users.json 
- **simulator.py** - Attack orchestrator (manual + auto suite)

## Components

### 1. server.py (Authentication Server)

Authentication server with configurable hash modes and defenses.

Endpoints:
- POST /register - Create new user
- POST /login - Authenticate user
- POST /login_totp - Authenticate with TOTP

CLI flags:
```
--hash <mode>       sha256 | bcrypt | argon2id (default: sha256)
--rate-limit        Enable rate limiting
--lockout           Enable account lockout
--captcha           Enable CAPTCHA simulation
--totp              Enable TOTP requirement
--pepper            Enable pepper
--port <num>        Server port (default: 8000)
```

Config is also saved/loaded from server_config.json for persistence. <br>
CLI flags define explicit experiment configurations and update the stored config.

| CLI Arguments | Hash Mode | Defenses | Config Update |
|---------------|-----------|----------|---------------|
| `python server.py` | From config | From config | No change (uses stored config) |
| `python server.py --hash sha256` | sha256 | All disabled | Hash updated, defenses cleared |
| `python server.py --hash bcrypt --pepper` | bcrypt | Only pepper enabled | Both updated explicitly |
| `python server.py --pepper --rate-limit` | From config | Only specified enabled | Defenses updated, hash kept |
| `python server.py --port 9000` | From config | From config | Only port updated |


### 2. setup_db.py (Database Seeder)

Populates database with users from users.json using current server configuration.

Behavior:
- Reads server_config.json (hash mode, pepper setting)
- Loads 30 users from users.json
- Clears database
- Hashes passwords with current configuration
- Inserts users into database

Usage:
```bash
python src/server/setup_db.py
```

Note: Can run while server is running (SQLite allows concurrent access).

### 3. simulator.py (Attack Orchestrator)

Two modes: manual execution OR automated test suite.

**Manual Mode:**
```bash
python src/simulator/simulator.py --manual
```
Note: Assumes server is already running and database is seeded.

**Auto Suite Mode (Default):**
```bash
python src/simulator/simulator.py --all
```

Runs 11 pre-defined scenarios (3 hash baselines + 5 individual defenses + 3 combinations) automatically.

CLI Flags (optional for running a specific scenario):
```
--hash <mode>       Specify hash mode
--rate-limit        Enable rate limiting
--lockout           Enable lockout
--captcha           Enable CAPTCHA
--totp              Enable TOTP
--pepper            Enable pepper
```

## Data Flow

### Manual Workflow

```
Terminal 1: Start server with configuration
  $ python src/server/server.py --hash bcrypt --pepper --rate-limit

Terminal 2: Seed database (optional - or use /register API)
  $ python src/server/setup_db.py

Terminal 3: Run attacks in manual mode
  $ python src/simulator/simulator.py --manual

Server logs to: src/logs/attempts/
Logs created:
  - attempts_bcrypt_pepper_ratelimit_password_spraying.log
  - attempts_bcrypt_pepper_ratelimit_brute_force.log
```

### Automated Test Suite Workflow

```
$ python src/simulator/simulator.py --all

Behind the scenes (11 scenarios total):
  For each scenario in SCENARIOS:
    1. Start server: python server.py --hash <mode> <defenses> &
    2. Seed database: python setup_db.py
    3. Wait for server ready
    4. Run password-spraying attack via HTTP to /login
    5. Rename log: attempts_<hash>_<defenses>_password_spraying.log
    6. Restart server with same configuration
    7. Reset database: python setup_db.py (clean state for next attack)
    8. Run brute-force attacks via HTTP to /login
    9. Rename log: attempts_<hash>_<defenses>_brute_force.log
    10. Stop server

All logs saved to: src/logs/attempts/
Total attack runs: 22 (11 scenarios × 2 attack types)
```

## Log Format

### Directory Structure

```
src/logs/
+-- attempts/                        # All attack logs
    |-- attempts_sha256_none_password_spraying.log
    |-- attempts_sha256_none_brute_force.log
    |-- attempts_sha256_ratelimit_password_spraying.log
    |-- attempts_sha256_ratelimit_brute_force.log
    |-- attempts_bcrypt_none_password_spraying.log
    |-- attempts_bcrypt_none_brute_force.log
    |-- attempts_argon2id_none_password_spraying.log
    |-- attempts_argon2id_none_brute_force.log
    +-- ...
```

Both manual and auto modes save logs to `src/logs/attempts/`

### attempts_*.log Format (JSON lines)

Example filename: `attempts_bcrypt_pepper_ratelimit_bruteforce.log`

Each line is a JSON object representing one authentication attempt:
```json
{
  "timestamp": "2025-01-16T15:30:45.123Z",
  "username": "user01",

  "hash_mode": "bcrypt",
  "protection_flags": {
    "rate_limit": true,
    "lockout": false,
    "captcha": false,
    "totp": false,
    "pepper": true
  },

  "result": "failure",
  "failure_reason": "INVALID_CREDENTIALS",
  "totp_required": false,
  "retry_after": 0.5,

  "latency_ms": null,
  "cpu_time_ms": null,
  "memory_delta_kb": null,

  "group_seed": "519933725",
}
```

## users.json Format

Location: src/data/users.json

```
{
  "users": [
    {
      "username": "user01",
      "password": "123456",
      "category": "weak",
      "totp_secret": "JBSWY3DPEHPK3PXP"
    },
    {
      "username": "user02",
      "password": "MyD0g&Cat!",
      "category": "medium",
      "totp_secret": "KBSWY3DPEHPK3PXQ"
    }
  ],
  "group_seed": "519933725"
}
```

Categories:
- weak: 10 users (common passwords, short, dictionary words)
- medium: 10 users (some complexity, predictable patterns)
- strong: 10 users (random, long, mixed characters)

## Database

Location: src/server/db/auth.db

SQLite database storing user credentials and authentication state.

**Tables:**

1. **users** - User credentials
   - username (TEXT PRIMARY KEY)
   - password_hash (TEXT)
   - salt (TEXT)
   - totp_secret (TEXT, nullable)

2. **auth_state** - Defense mechanism state tracking
   - username (TEXT PRIMARY KEY)
   - failed_attempts (INTEGER) - Used by lockout and CAPTCHA defenses
   - locked_until (REAL, nullable) - Unix timestamp for lockout expiration
   - last_attempt (REAL, nullable) - Unix timestamp of last login attempt

**Notes:**
- Database is reset between attack types within each scenario (clean state isolation)
- Pepper value is NOT stored in database (kept in .env file)
- TOTP secrets are pre-generated and stored per user

## server_config.json Format

Location: src/server/config/server_config.json

```
{
  "host": "0.0.0.0",
  "port": 8000,
  "hash_mode": "bcrypt",
  "defenses": {
    "rate_limit": true,
    "lockout": false,
    "captcha": false,
    "totp": false,
    "pepper": true
  },
  "group_seed": "519933725"
}
```

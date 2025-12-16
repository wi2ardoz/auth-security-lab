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
- **setup_db.py** - Database seeding from users.json
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

Two modes: manual attack OR automated experiment suite.

**Manual Mode:**
```bash
python src/simulator/simulator.py --attack brute-force --target user01
python src/simulator/simulator.py --attack password-spraying
```
CLI Flags:
```
--attack <type>     brute-force | password-spraying (manual mode)
--target <user>     Target username (for brute-force in manual mode)
```
Note: Assumes server is already running and database is seeded.

**Auto Suite Mode (Default):**
```bash
python src/simulator/simulator.py
```

Runs all combinations of hash × defenses × attacks automatically.

## Data Flow

### Manual Workflow

```
Terminal 1: Start server with configuration
  $ python src/server/server.py --hash bcrypt --pepper --rate-limit

Terminal 2: Seed database (optional - or use /register API)
  $ python src/server/setup_db.py

Terminal 3: Run single attack
  $ python src/simulator/simulator.py --attack brute-force --target user01

Server logs to: src/logs/attempts/attempts_<hash>_<defenses>.log
After attack completes, log is renamed to include attack type.
```

### Automated Test Suite Workflow

```
$ python src/simulator/simulator.py

Behind the scenes:
  For each hash_mode in [sha256, bcrypt, argon2id]:
    For each defense_combo in [none, pepper, rate-limit, ...]:
      For each attack_type in [brute-force, password-spraying]:
        1. Start server: python server.py --hash <mode> <defenses> &
        2. Seed database: python setup_db.py
        3. Wait for server ready
        4. Run attack via HTTP requests to /login
        5. Stop server
        6. Rename log: attempts_<hash>_<defenses>.log ->
                       attempts_<hash>_<defenses>_<attack>.log
        7. Move log to suite directory

  After all experiments:
    Generate summary.csv from all logs
```

## Log Format

### Directory Structure

```
src/logs/
|-- suite_20250116_143022/          # Auto suite mode
|   |-- attempts_sha256_none_bruteforce.log
|   |-- attempts_sha256_none_passwordspraying.log
|   |-- attempts_sha256_pepper_bruteforce.log
|   |-- attempts_bcrypt_none_bruteforce.log
|   |-- attempts_bcrypt_pepper_bruteforce.log
|   |-- ...
|   +-- summary.csv                 # Aggregate statistics
|
|-- suite_20250116_151500/          # Next suite run
    |-- attempts_*.log
    +-- summary.csv
```

**Manual mode:** Logs go to `src/logs/attempts/attempts_<hash>_<defenses>_<attack>.log`

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
  "latency_ms": 245,
  "group_seed": "519933725"
}
```

### summary.csv Format

Location: Inside each suite directory (e.g., `suite_20250116_143022/summary.csv`)

Columns:
```
hash_mode, rate_limit, lockout, captcha, totp, pepper, attack_type,
total_attempts, attempts_per_second, time_to_first_success,
average_latency_ms, success_rate_weak, success_rate_medium,
success_rate_strong, group_seed
```

Example row:
```
bcrypt,true,false,false,false,true,brute_force,1523,12.4,122.5,243,0.8,0.2,0.0,519933725
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

Location: src/server/db/

SQLite database storing user credentials and authentication state.

Files:
- auth.db - Main database with users table

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
  "pepper_value": "secret_pepper_not_in_db",
  "group_seed": "519933725"
}
```

## Report Generation

Steps:
1. List all files in src/logs/suite_DATE_HOUR/
2. For each log file:
   - Parse filename for hash_mode, defenses, attack_type
   - Read JSON lines
   - Join with users.json to get password category
   - Calculate metrics:
      - total_attempts = count of lines
      - attempts_per_second = total / (last_timestamp - first_timestamp)
      - time_to_first_success = first success timestamp - first timestamp
      - average_latency_ms = mean of latency_ms
      - success_rate_by_category = successes / attempts per category
3. Append row to summary.csv

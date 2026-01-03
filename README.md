# Maman 16 - Password Authentication Mechanisms Analysis

**Course:** Computer Security (20940) <br>
**Institution:** Open University of Israel <br>
**Project Type:** Comparative Analysis of Password-Based Authentication Mechanisms <br>
**Authors**: Liad Oz, Michael Feldman  <br>
**Emails**: ozliad10@gmail.com, Michaelfeldman8@gmail.com  <br>
**SEED_GROUP**: 519933725

## Overview

This project performs a comparative analysis of password-based authentication mechanisms, examining how different password storage methods and authentication systems withstand common attack methods such as Brute-Force and Password-Spraying attacks.

The project evaluates the effectiveness of various protection mechanisms including rate limiting, account lockout, CAPTCHA, TOTP (Time-based One-Time Password), salt, and pepper.

## Project Objectives

### Main Objective
Conduct a reproducible experiment comparing password hashing and authentication mechanisms (bcrypt, Argon2, SHA-256+salt), examining the impact of various protection mechanisms (salt, pepper, rate limiting, account lockout, CAPTCHA, TOTP), and performing statistical analysis of the results.

### Additional Objectives
- Measure time-to-crack and success rate under various protection mechanisms
- Quantify the impact of each protection mechanism individually and in combination
- Evaluate the trade-off between usability and performance for each approach
- Generate a concise research report summarizing experimental findings

## Prerequisites

- Python 3.8 or higher
- Git
- pip (Python package manager)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd Project
```

### 2. Create and Activate Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Project Structure

```
Project/
|-- src/
|   |-- server/
|   |   |-- defenses/                # Defense implementations
|   |   |   |-- __init__.py
|   |   |   |-- hash.py              # Password hashing (sha256/bcrypt/argon2id)
|   |   |   |-- rate_limiter.py      # Rate limiting defense
|   |   |   |-- account_lockout.py   # Account lockout defense
|   |   |   |-- captcha.py           # CAPTCHA defense
|   |   |   |-- totp.py              # TOTP two-factor authentication
|   |   |   +-- defenses_const.py    # Defense constants
|   |   |-- utils/                   # Server utilities
|   |   |   |-- __init__.py
|   |   |   |-- config.py            # Config load/save
|   |   |   |-- logger.py            # Authentication logging
|   |   |   |-- cli.py               # CLI parsing
|   |   |   +-- utils_const.py       # Config schema constants
|   |   |-- config/
|   |   |   +-- server_config.json   # Hash mode + defense toggles
|   |   |-- db/                      # SQLite database
|   |   |   +-- auth.db
|   |   |-- auth_service.py          # Authentication service orchestrator
|   |   |-- database.py              # SQLite database management
|   |   |-- server.py                # Auth server (FastAPI + SQLite)
|   |   |-- server_const.py          # Server constants
|   |   +-- setup_db.py              # Database seeder from users.json
|   |
|   |-- simulator/
|   |   |-- simulator.py             # Attack orchestrator (manual + auto suite)
|   |   |-- simulator_const.py       # Simulator constants and scenarios
|   |   |-- attacks.py               # Attack implementations
|   |   +-- attacks_const.py         # Attack constants
|   |
|   |-- data/
|   |   |-- users.json               # 30 test accounts (weak/medium/strong)
|   |   +-- passwords.json           # Password list for attacks
|   |
|   +-- logs/
|       +-- attempts/                # Attack logs
|           |-- attempts_sha256_none_password_spraying.log
|           |-- attempts_sha256_none_brute_force.log
|           |-- attempts_bcrypt_none_password_spraying.log
|           +-- ...
|
|-- requirements.txt
|-- design.md
+-- README.md
```

## Development Workflow

### Starting Work

```bash
cd Project
source venv/bin/activate
```

### Installing Packages

```bash
pip install <package-name>
pip freeze > requirements.txt
```

## Usage

### Automated Test Suite (Recommended)

Run all scenarios automatically:

```bash
python src/simulator/simulator.py --all
```

**Output:**
- Real-time progress for each scenario
- Results saved to `src/logs/attempts/`
- Log files: `attempts_<hash>_<defenses>_<attack>.log`

**What it does:**
- Tests 11 pre-defined scenarios (3 hash baselines + 5 individual defenses + 3 combinations)

---

### Manual Execution (Single Experiment)

**Step 1: Start server with configuration**

```bash
python src/server/server.py --hash bcrypt --pepper --rate-limit
```

Server flags:
```
--hash <mode>       sha256 | bcrypt | argon2id (default: sha256)
--rate-limit        Enable rate limiting
--lockout           Enable account lockout
--captcha           Enable CAPTCHA simulation
--totp              Enable TOTP requirement
--pepper            Enable pepper
--port <num>        Server port (default: 8000)
```

**Configuration Behavior:**
CLI flags update `server_config.json` and define experiment configuration.

| CLI Arguments | Hash Mode | Defenses | Config Update |
|---------------|-----------|----------|---------------|
| `python server.py` | From config | From config | No change |
| `python server.py --hash sha256` | sha256 | All disabled | Hash updated, defenses cleared |
| `python server.py --hash bcrypt --pepper` | bcrypt | Only pepper | Both updated |
| `python server.py --pepper --rate-limit` | From config | Only specified | Defenses updated |

**Step 2: Seed database (Optional)**

```bash
# Option A: Use setup_db.py (seeds 30 users + resets the authentication state DB table)
python src/server/setup_db.py

# Option B: Use /register API (manual registration)
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user01","password":"123456"}'
```

**Step 3: Run attack**

```bash
# Run both attacks (password-spraying + brute-force) in manual mode
python src/simulator/simulator.py --manual
```

**Note:** The `--manual` flag runs attacks without starting/stopping the server automatically. You must start the server manually in Step 1.

### Deactivating Environment

```bash
deactivate
```

## Key Concepts

### TOTP (Time-based One-Time Password)
Two-factor authentication mechanism generating temporary codes derived from a shared secret. Each code is valid for a short time period (typically 30 seconds).

### Password-Spraying
Attack method using a small set of common passwords against many user accounts, as opposed to Brute-Force which targets a single account. Successfully compromised users are immediately removed from the target list to prevent redundant attempts.

### Pepper
Global secret value added to passwords before hashing, stored separately from the database. Unlike salt (which is per-user and stored with the hash), pepper is global and kept as a secret.

### SEED_GROUP
Unique identifier for each team, calculated as: `SEED_GROUP = ID1 XOR ID2` (bitwise XOR of both team members' IDs). Used for experiment uniqueness and verification.

## Experiment Protocol

### 1. Dataset Creation
- 30 test accounts: 10 weak, 10 medium, 10 strong passwords
- Document classification criteria for each category
- One password will be SEED_GROUP value

### 2. Hash Mechanisms
- SHA-256 + per-user salt
- bcrypt (cost = 12)
- Argon2id (time = 1, memory = 64 MB, parallelism = 1)

### 3. Protection Mechanisms
- Rate limiting
- Account lockout
- CAPTCHA (simulated)
- TOTP
- Pepper

### 4. Attack Scenarios
- Brute-Force: Targeted attack on multiple accounts ordered by password strength
- Password-Spraying: Common passwords across multiple accounts

### 5. Metrics Collection
- Total attempts
- Time-to-crack
- Attempts per second
- Success rate by password category
- Average latency (ms)
- CPU/Memory usage

## Project Deliverables

1. **Research Report**: Introduction, methodology, results, analysis, discussion, ethical considerations, and references
2. **Raw Logs**: Structured data (JSON) of authentication attempts and results
3. **Configuration Files**: Environment configuration (no secret keys)
4. **Presentation**: Brief summary of objectives, configuration, and findings
5. **Demo Video**: Demonstration of environment and key results

## Work Plan (5 Weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| 1 | Literature review, tool selection, Server setup, User dataset creation | Server App + Basic logs | 
| 2 | Simulator, Brute-Force & Password-Spraying testing | Client App + Attack logs + Interim report |
| 3 | Add protection mechanisms (Rate-Limit, account lockout, TOTP, CAPTCHA), repeat tests | Complete logs + Analysis data |
| 4-5 | Data analysis, report writing, presentation, and demo video | Final submission (Report, Presentation, Video) |

## Version History

- **v1.0** (Ready Version)
  - Adjust maximum password to try for password-spray attack. 
- **v0.4** (Integration Server-Simulator)
  - Password spraying: Remove cracked users from target list
  - Brute force: Attack users ordered by password strength
  - Add more metrics fields to logs 
  - Fix integration bugs
- **v0.3** (Attack Mechanism and Simulator)
  - Create Simulator for running attacks both manually and automatically
  - Create attack scenarios
  - Add attacks API
  - Relocate pepper value for .env file (not ignored for educational purpose only)
- **v0.2** (Defense Mechanisms)
  - Add protection mechanisms: Rate-Limit, account lockout, TOTP, CAPTCHA
  - Add `auth_state` table for database
  - Refactor authentication service in `auth_service.py`
  - Pepper support via environment variable
- **v0.1** (Server Implementation)
  - FastAPI-based auth server with CLI configuration and SQLite DB
  - Database seeder: src/server/setup_db.py (imports 30 test accounts from src/data/users.json)
  - Password hashing implementations: SHA-256+salt, bcrypt, Argon2id
  - Global pepper support and per-user salt handling
  - Structured server logging: login attempts
  - Config management: src/server/config/server_config.json
- **v0.0** (Initial Release)
  - Python project structure initialized
  - Virtual environment configured
  - README and design documents created

## License

This project is for academic purposes only as part of the Computer Security course (Maman 16).
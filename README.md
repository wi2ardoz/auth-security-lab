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
|   |   |-- server.py               # Auth server (FastAPI + SQLite)
|   |   |-- server_const.py         # Server constants
|   |   |-- setup_db.py             # DB initialization
|   |   |-- config/
|   |   |   +-- server_config.json  # Hash mode + defense toggles
|   |   |-- db/                     # SQLite database
|   |   +-- defenses/               # Defense implementations
|   |
|   |-- attacker/
|   |   |-- attacker.py             # Attack client (brute-force, spray)
|   |   +-- attacker_const.py       # Attacker constants
|   |
|   |-- data/
|   |   +-- users.json              # 30 test accounts (weak/medium/strong)
|   |
|   |-- logs/
|   |   |-- attempts/               # Raw attempt logs per experiment
|   |   |   |-- .
|   |   |   |-- .
|   |   |   +-- attempts_<hash>_<defenses>_<attack>.log
|   |   |
|   |   +-- summary/
|   |       +-- summary.csv         # Aggregated results from all experiments
|   |
|   |-- simulator.py                # Interactive CLI menu
|   +-- simulator_const.py          # Simulator constants
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

### Running the Simulator (Recommended)

```bash
python src/simulator.py
```

### Manual Execution (Advanced)

Run server with specific configuration:
```bash
python src/server/server.py --hash bcrypt --rate-limit --lockout --pepper
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

Run attacker against the server:
```bash
python src/attacker/attacker.py --target http://localhost:8000 --attack brute_force --user user01
python src/attacker/attacker.py --target http://localhost:8000 --attack spray --wordlist common.txt
```

Attacker flags:
```
--target <url>      Server URL (default: http://localhost:8000)
--attack <type>     brute_force | spray
--user <username>   Target user (for brute_force)
--wordlist <file>   Password list file
--max-attempts <n>  Limit attempts (default: 50000)
```

### Deactivating Environment

```bash
deactivate
```

## Key Concepts

### TOTP (Time-based One-Time Password)
Two-factor authentication mechanism generating temporary codes derived from a shared secret. Each code is valid for a short time period (typically 30 seconds).

### Password-Spraying
Attack method using a small set of common passwords against many user accounts, as opposed to Brute-Force which targets a single account.

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
- Rate limiting (per-user and global)
- Account lockout
- CAPTCHA (simulated)
- TOTP
- Pepper

### 4. Attack Scenarios
- Brute-Force: Targeted attack on single account
- Password-Spraying: Common passwords across multiple accounts
- Combined protection mechanisms

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
| 1 | Literature review, tool selection, Server setup | Server App + Basic logs | 
| 2 | Client CLI setup, User dataset creation, Brute-Force & Password-Spraying testing | Client App + Attack logs + Interim report |
| 3 | Add protection mechanisms (Rate-Limit, Pepper, TOTP, CAPTCHA), repeat tests | Complete logs + Analysis data |
| 4-5 | Data analysis, report writing, presentation, and demo video | Final submission (Report, Presentation, Video) |

## Version History

- **v1.0.0** (Initial Release) - Project setup and documentation
  - Python project structure initialized
  - Virtual environment configured
  - README and design documents created

## License

This project is for academic purposes only as part of the Computer Security course (Maman 16).
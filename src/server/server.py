"""
server.py
FastAPI server for user registration and login with SQLite database.
"""

import sqlite3

import server_const as server_const
import uvicorn
from database import get_user, init_database, insert_user
from defenses import hash_password, verify_password
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils import get_default_config, load_config, save_config


# Request models
class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginTOTPRequest(BaseModel):
    username: str
    password: str
    totp_code: str


# FastAPI app
app = FastAPI()


# Registration endpoint
@app.post("/register")
async def register_user(request: RegisterRequest):
    try:
        # TODO: Load from config
        hash_mode = server_const.DEFAULT_HASH_MODE
        pepper = None

        # Hash the password
        password_hash, salt = hash_password(
            request.password, hash_mode, salt=None, pepper=pepper
        )

        # TODO: Generate TOTP secret
        totp_secret = None

        success = insert_user(request.username, password_hash, salt, totp_secret)
        if not success:
            return {
                "status": server_const.SERVER_FAILURE,
                "message": server_const.SERVER_MSG_REGISTER_UNIQUE_FAIL,
            }
        return {
            "status": server_const.SERVER_SUCCESS,
            "message": server_const.SERVER_MSG_REGISTER_OK,
        }

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


# Login endpoint
@app.post("/login")
async def login_user(request: LoginRequest):
    try:
        user = get_user(request.username)
        if user is None:
            return {
                "status": server_const.SERVER_FAILURE,
                "message": server_const.SERVER_MSG_LOGIN_INVALID,
            }
        username, password_hash, salt, totp_secret = user

        # TODO: Load from config
        hash_mode = server_const.DEFAULT_HASH_MODE
        pepper = None

        verified = verify_password(
            request.password, password_hash, hash_mode, salt=salt, pepper=pepper
        )
        if verified:
            return {
                "status": server_const.SERVER_SUCCESS,
                "message": server_const.SERVER_MSG_LOGIN_OK,
            }
        else:
            return {
                "status": server_const.SERVER_FAILURE,
                "message": server_const.SERVER_MSG_LOGIN_INVALID,
            }

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")


# TOTP Login endpoint
@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    # TODO: Implement later
    return {
        "status": server_const.SERVER_FAILURE,
        "message": "TOTP not implemented yet",
    }


def initialize_config():
    """
    Initialize server configuration.
    Loads from file or creates default if not found.

    :return: Configuration dictionary
    """
    try:
        config = load_config(server_const.CONFIG_PATH)
        print(f"✓ Loaded configuration from {server_const.CONFIG_PATH}")
        print(
            f"  Hash: {config['hash_mode']}, "
            f"Defenses: {[k for k, v in config['defenses'].items() if v] or 'none'}"
        )
        return config

    except FileNotFoundError:
        print(f"⚠ Config file not found: {server_const.CONFIG_PATH}")
        print(f"  Creating default configuration...")

        config = get_default_config()
        save_config(config, server_const.CONFIG_PATH)

        print(f"  Created default config at {server_const.CONFIG_PATH}")
        print(f"⚠ Hash: {config['hash_mode']}, Defenses: none")
        return config

    except Exception as e:
        print(f"✗ Error loading config: {e}")
        raise


if __name__ == "__main__":

    # Initialize database
    init_database()

    # Initialize configuration and store in app.state
    app.state.config = initialize_config()

    # Start server
    host = app.state.config["host"]
    port = app.state.config["port"]
    print(f"✓ Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)

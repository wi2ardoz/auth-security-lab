"""
Authentication Server - FastAPI + SQLite
"""
from fastapi import FastAPI
from pydantic import BaseModel
import server_const as const 

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

app = FastAPI()

@app.post("/register")
async def register_user(request: RegisterRequest):
    username = request.username
    password = request.password
    # TODO
    return {"status": const.SERVER_SUCCESS,
            "message": const.SERVER_MSG_REGISTER_OK}
    
@app.post("/login")
async def login_user(request: LoginRequest):
    username = request.username
    password = request.password
    #TODO
    return {"status": const.SERVER_SUCCESS,
            "message": const.SERVER_MSG_LOGIN_OK}

@app.post("/login_totp")
async def login_totp_user(request: LoginTOTPRequest):
    username = request.username
    password = request.password
    totp_code = request.totp_code
    #TODO
    return {"status": const.SERVER_SUCCESS,
            "message": const.SERVER_MSG_LOGIN_TOTP_OK}

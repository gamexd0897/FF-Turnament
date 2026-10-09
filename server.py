
import os
import hashlib
import hmac
import json
from urllib.parse import parse_qsl
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from supabase import create_client

app = FastAPI(title="Free Fire Tournament API")


def get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        raise HTTPException(
            status_code=500,
            detail="Server database configuration is missing"
        )

    return create_client(url, key)


def verify_telegram_data(init_data: str):
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not bot_token or not init_data:
        raise HTTPException(status_code=401, detail="Telegram login required")

    values = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = values.pop("hash", None)
    auth_date = values.get("auth_date")

    if not received_hash or not auth_date:
        raise HTTPException(status_code=401, detail="Invalid Telegram data")

    try:
        if abs(datetime.now(timezone.utc).timestamp() - int(auth_date)) > 300:
            raise HTTPException(status_code=401, detail="Login expired")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid login time")

    data_check_string = "\n".join(
        f"{key}={value}" for key, value in sorted(values.items())
    )

    secret_key = hmac.new(
        b"WebAppData",
        bot_token.encode(),
        hashlib.sha256
    ).digest()

    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise HTTPException(status_code=401, detail="Telegram verification failed")

    try:
        user = json.loads(values["user"])
        return int(user["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Telegram user missing")


@app.get("/")
def home():
    return {"status": "Free Fire Tournament API is running"}

class RegistrationData(BaseModel):
    squad_name: str
    player1_uid: str
    player1_username: str
    player2_uid: str
    player2_username: str
    player3_uid: str
    player3_username: str
    player4_uid: str
    player4_username: str



@app.post("/register")
def register(
    data: RegistrationData,
    x_telegram_init_data: str = Header(default="")
):
    user_id = verify_telegram_data(x_telegram_init_data)
    supabase = get_supabase()

    existing = (
        supabase.table("profiles")
        .select("id")
        .eq("telegram_user_id", user_id)
        .execute()
    )

    if len(existing.data or []) >= 5:
        raise HTTPException(
            status_code=400,
            detail="Maximum 5 profiles allowed"
        )

    profile_data = data.dict()
    profile_data["telegram_user_id"] = user_id

    try:
        result = (
            supabase.table("profiles")
            .insert(profile_data)
            .execute()
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Registration could not be saved"
        )

    return {
        "success": True,
        "message": "Registration saved successfully",
        "profile": result.data[0] if result.data else None
    }
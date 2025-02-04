rom fastapi import FastAPI, Depends, Request, Security, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKeyHeader
import httpx
import os
import logging
import bcrypt
import sqlite3
from pydantic import BaseModel
from app.database import init_db, get_db_connection  # Assuming database.py is in the same directory

app = FastAPI()

# Initialize database
init_db()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

security = HTTPBasic()

# --- API Key Authentication ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

def verify_api_key(api_key: str = Security(api_key_header)):
    # Check API key validity in SQLite database.
    logger.debug("DEBUG: Inside verify_api_key")
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name, email, usage_limit, requests_made, is_active FROM api_keys WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        logger.warning(f"❌ Invalid API Key: {api_key}")
        raise HTTPException(status_code=403, detail="Invalid API Key")

    name, email, usage_limit, requests_made, is_active = user

    if not is_active:
        logger.warning(f"🚫 API Key for {name} ({email}) is deactivated.")
        raise HTTPException(status_code=403, detail="API Key is deactivated")

    if requests_made >= usage_limit:
        logger.warning(f"❌ API Key limit exceeded for {name} ({email}).")
        raise HTTPException(status_code=429, detail="API Key usage limit exceeded")

    # Increment API usage count efficiently
    if requests_made % 10 == 0:  # Batch update every 10th request
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET requests_made = requests_made + 10 WHERE api_key = ?", (api_key,))
        conn.commit()
        conn.close()

    logger.info(f"✅ API Key validated for {name} ({email}).")
    return api_key

# --- Proxy Configuration ---
NIM_BASE_URL = os.getenv("NIM_BASE_URL", "http://nim:8000")

# --- Admin Authentication ---
security = HTTPBasic(auto_error=False)  # Allows custom error messages

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    logger.debug("DEBUG: Inside verify_admin")

    stored_username = os.getenv("ADMIN_USERNAME", "admin")
    stored_hashed_password = os.getenv("ADMIN_PASSWORD_HASH", "")

    if not stored_hashed_password:
        logger.error("❌ Admin credentials not set in environment")
        raise HTTPException(status_code=500, detail="Admin credentials not set in environment")

    if credentials.username != stored_username:
        logger.warning(f"⚠️ Unauthorized admin login attempt with username: {credentials.username}")
        raise HTTPException(status_code=403, detail="Invalid Admin Credentials")

    if not bcrypt.checkpw(credentials.password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        logger.warning(f"⚠️ Failed login attempt for admin: {stored_username}")
        raise HTTPException(status_code=403, detail="Invalid Admin Credentials")

    logger.info("✅ Admin authentication successful")
    return credentials.username

# --- API Key Management ---
class APIKeyCreate(BaseModel):
    name: str
    email: str
    api_key: str
    usage_limit: int = 1000

@app.post("/admin/create-api-key/")
def create_api_key(data: APIKeyCreate, admin: str = Depends(verify_admin)):
    # Admin: Add a new API key.
    logger.debug("DEBUG: Connecting to database")
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO api_keys (name, email, api_key, usage_limit, is_active) VALUES (?, ?, ?, ?, ?)",
            (data.name, data.email, data.api_key, data.usage_limit, 1),  # Set active by default
        )
        conn.commit()
        logger.debug(f"DEBUG: Created API key: {data.api_key}")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email or API key already exists")
    finally:
        conn.close()

    return {"message": "API key created successfully", "api_key": data.api_key}

@app.get("/admin/list-api-keys/")
def list_api_keys(admin: str = Depends(verify_admin)):
    logger.debug("DEBUG: Inside list_api_keys")
    conn = get_db_connection()
    cursor = conn.cursor()

    logger.debug("DEBUG: Fetching API keys")
    cursor.execute("SELECT id, name, email, api_key, usage_limit, requests_made, is_active, created_at FROM api_keys")
    api_keys = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "api_key": row[3],
            "usage_limit": row[4],
            "requests_made": row[5],
            "is_active": bool(row[6]),
            "created_at": row[7]
        }
        for row in api_keys
    ]

@app.delete("/admin/delete-api-key/{api_key}/")
def delete_api_key(api_key: str, admin: str = Depends(verify_admin)):
    # Admin: Delete an API key.
    logger.debug("DEBUG: Connecting to database")
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
        if cursor.rowcount == 0:
            logger.debug(f"DEBUG: API key not found: {api_key}")
            raise HTTPException(status_code=404, detail="API key not found")
        conn.commit()
        logger.debug(f"DEBUG: Deleted API key: {api_key}")
    except sqlite3.Error as e:
        logger.error(f"DEBUG: Database error: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        conn.close()

    return {"message": "API key deleted successfully"}

# --- Proxy Logic ---

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request, path: str, api_key: str = Depends(verify_api_key)):
    # Forward requests to NIM with API Key validation, excluding /admin routes.
    if path.startswith("admin/"):
        logger.debug("DEBUG: Admin path detected, not proxying")
        raise HTTPException(status_code=404, detail="Not Found")  # Or handle it with an appropriate admin function

    logger.debug(f"DEBUG: Proxying request to NIM at {path}")
    url = f"{NIM_BASE_URL}/{path}"
    headers = {key: value for key, value in request.headers.items() if key.lower() != "host"}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=await request.body(),
                timeout=10.0  # Avoid hanging requests
            )
            response.raise_for_status()  # Raise an error for 4xx/5xx responses
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"🚨 NIM API Error {e.response.status_code}: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail="NIM API Error")
        except httpx.RequestError as e:
            logger.error(f"🚨 Failed to reach NIM at {url}: {e}")
            raise HTTPException(status_code=503, detail="NIM Service Unavailable")
        except Exception as e:
            logger.error(f"🚨 An unexpected error occurred: {e}")
            raise HTTPException(status_code=500, detail="Internal Server Error")

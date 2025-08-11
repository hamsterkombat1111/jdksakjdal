from fastapi import FastAPI, HTTPException, Request, Depends, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
import os
import hashlib
import uuid
from typing import List, Optional
import httpx
from user_agents import parse
import asyncio
import json
import aiofiles
from pathlib import Path

# Environment variables
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "prank_site_db")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = int(os.environ.get("TELEGRAM_CHAT_ID", "-1002727327119"))

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS.split(",") if CORS_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
@app.on_event("startup")
async def startup_db_client():
    app.mongodb_client = AsyncIOMotorClient(MONGO_URL)
    app.mongodb = app.mongodb_client[DB_NAME]
    
    # Create admin user
    admin_exists = await app.mongodb.users.find_one({"username": "admin"})
    if not admin_exists:
        admin_password = hashlib.sha256("qwerqwer".encode()).hexdigest()
        await app.mongodb.users.insert_one({
            "id": str(uuid.uuid4()),
            "username": "admin",
            "password": admin_password,
            "role": "admin",
            "created_at": datetime.utcnow()
        })

@app.on_event("shutdown")
async def shutdown_db_client():
    app.mongodb_client.close()

# Security
security = HTTPBearer(auto_error=False)

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class AdminCreate(BaseModel):
    name: str
    telegram_handle: str
    
class BlockIPRequest(BaseModel):
    ip: str
    reason: str

# Helper functions
async def send_telegram_message(message: str):
    """Send message to Telegram channel"""
    if not TELEGRAM_TOKEN:
        return
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data)
            return response.json()
    except Exception as e:
        print(f"Failed to send Telegram message: {e}")

def get_client_info(request: Request):
    """Extract client information from request"""
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Parse user agent
    parsed_ua = parse(user_agent)
    
    return {
        "ip": ip,
        "browser": f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}",
        "os": f"{parsed_ua.os.family} {parsed_ua.os.version_string}",
        "device": parsed_ua.device.family,
        "user_agent": user_agent
    }

async def log_visit(request: Request, background_tasks: BackgroundTasks):
    """Log site visit"""
    client_info = get_client_info(request)
    
    # Check if IP is blocked
    blocked_ip = await app.mongodb.blocked_ips.find_one({"ip": client_info["ip"]})
    if blocked_ip:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Log to database
    log_data = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow(),
        **client_info,
        "endpoint": str(request.url.path)
    }
    
    await app.mongodb.visit_logs.insert_one(log_data)
    
    # Send to Telegram
    message = f"""
🌐 <b>Новый визит на сайт</b>

📍 <b>IP:</b> {client_info['ip']}
🌐 <b>Браузер:</b> {client_info['browser']}
💻 <b>ОС:</b> {client_info['os']}
📱 <b>Устройство:</b> {client_info['device']}
📄 <b>Страница:</b> {request.url.path}
🕐 <b>Время:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

<code>{client_info['user_agent']}</code>
    """
    
    background_tasks.add_task(send_telegram_message, message)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    if not credentials:
        return None
    
    try:
        # Simple token validation (in production, use JWT)
        user = await app.mongodb.users.find_one({"token": credentials.credentials})
        return user
    except:
        return None

# Middleware for IP blocking and logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Skip logging for some endpoints
    skip_paths = ["/docs", "/openapi.json", "/favicon.ico"]
    if request.url.path not in skip_paths:
        try:
            # Check IP blocking for main pages
            if request.url.path == "/" or request.url.path.startswith("/api/visit"):
                client_info = get_client_info(request)
                blocked_ip = await app.mongodb.blocked_ips.find_one({"ip": client_info["ip"]})
                if blocked_ip:
                    return HTTPException(status_code=403, detail="Access denied")
        except:
            pass
    
    response = await call_next(request)
    return response

# API Routes
@app.get("/api/visit")
async def log_site_visit(request: Request, background_tasks: BackgroundTasks):
    """Log site visit"""
    await log_visit(request, background_tasks)
    return {"status": "logged"}

@app.post("/api/login")  
async def login(login_request: LoginRequest):
    """Login endpoint"""
    password_hash = hashlib.sha256(login_request.password.encode()).hexdigest()
    
    user = await app.mongodb.users.find_one({
        "username": login_request.username,
        "password": password_hash
    })
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate simple token (in production, use JWT)
    token = str(uuid.uuid4())
    await app.mongodb.users.update_one(
        {"id": user["id"]},
        {"$set": {"token": token, "last_login": datetime.utcnow()}}
    )
    
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"]
    }

@app.get("/api/admins")
async def get_admins():
    """Get list of administrators"""
    admins = []
    async for admin in app.mongodb.telegram_admins.find():
        admins.append({
            "id": admin.get("id"),
            "name": admin.get("name"),
            "telegram_handle": admin.get("telegram_handle"),
            "created_at": admin.get("created_at")
        })
    return admins

@app.post("/api/admins")
async def create_admin(admin_data: AdminCreate, user = Depends(get_current_user)):
    """Create new admin (requires authentication)"""
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    admin = {
        "id": str(uuid.uuid4()),
        "name": admin_data.name,
        "telegram_handle": admin_data.telegram_handle,
        "created_at": datetime.utcnow()
    }
    
    result = await app.mongodb.telegram_admins.insert_one(admin)
    
    # Return the admin data without MongoDB ObjectId
    return {
        "id": admin["id"],
        "name": admin["name"],
        "telegram_handle": admin["telegram_handle"],
        "created_at": admin["created_at"]
    }

@app.delete("/api/admins/{admin_id}")
async def delete_admin(admin_id: str, user = Depends(get_current_user)):
    """Delete admin"""
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await app.mongodb.telegram_admins.delete_one({"id": admin_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    return {"message": "Admin deleted"}

@app.get("/api/blocked-ips")
async def get_blocked_ips(user = Depends(get_current_user)):
    """Get list of blocked IPs"""
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    blocked_ips = []
    async for ip in app.mongodb.blocked_ips.find():
        blocked_ips.append({
            "id": ip.get("id"),
            "ip": ip.get("ip"),
            "reason": ip.get("reason"),
            "blocked_at": ip.get("blocked_at")
        })
    return blocked_ips

@app.post("/api/block-ip")
async def block_ip(block_request: BlockIPRequest, user = Depends(get_current_user)):
    """Block IP address"""
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if already blocked
    existing = await app.mongodb.blocked_ips.find_one({"ip": block_request.ip})
    if existing:
        raise HTTPException(status_code=400, detail="IP already blocked")
    
    blocked_ip = {
        "id": str(uuid.uuid4()),
        "ip": block_request.ip,
        "reason": block_request.reason,
        "blocked_at": datetime.utcnow(),
        "blocked_by": user.get("username")
    }
    
    result = await app.mongodb.blocked_ips.insert_one(blocked_ip)
    
    # Return the blocked IP data without MongoDB ObjectId
    return {
        "id": blocked_ip["id"],
        "ip": blocked_ip["ip"],
        "reason": blocked_ip["reason"],
        "blocked_at": blocked_ip["blocked_at"],
        "blocked_by": blocked_ip["blocked_by"]
    }

@app.delete("/api/blocked-ips/{ip_id}")
async def unblock_ip(ip_id: str, user = Depends(get_current_user)):
    """Unblock IP address"""
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await app.mongodb.blocked_ips.delete_one({"id": ip_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Blocked IP not found")
    
    return {"message": "IP unblocked"}

@app.get("/api/logs")
async def get_visit_logs(user = Depends(get_current_user), limit: int = 50):
    """Get visit logs"""
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = []
    async for log in app.mongodb.visit_logs.find().sort("timestamp", -1).limit(limit):
        logs.append({
            "id": log.get("id"),
            "ip": log.get("ip"),
            "browser": log.get("browser"),
            "os": log.get("os"),
            "device": log.get("device"),
            "endpoint": log.get("endpoint"),
            "timestamp": log.get("timestamp")
        })
    return logs

@app.get("/")
async def root():
    return {"message": "PrankVZ Site API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
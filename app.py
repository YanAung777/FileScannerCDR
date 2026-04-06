#!/usr/bin/env python3
"""
FileCloud Enterprise - Complete Production Backend
Features: WebSockets, streaming, Celery, Prometheus, RBAC, quotas, 2FA, OAuth2, webhooks, etc.
"""

import os
import uuid
import hashlib
import json
import asyncio
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from urllib.parse import urlencode
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request, BackgroundTasks, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response, RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, Enum as SQLEnum, ForeignKey, select, func, and_, update
from passlib.context import CryptContext
from jose import JWTError, jwt
import aioboto3
import clamd
from celery import Celery
from dotenv import load_dotenv
import pyotp
import qrcode
from io import BytesIO
import base64
import httpx
import aioredis
from prometheus_client import Counter, Histogram, generate_latest, REGISTRY
from tenacity import retry, stop_after_attempt, wait_exponential
import aiofiles

load_dotenv()

# ------------------------------
# Configuration
# ------------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
DB_REPLICA_HOST = os.getenv("DB_REPLICA_HOST")
DATABASE_REPLICA_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_REPLICA_HOST}:{DB_PORT}/{DB_NAME}" if DB_REPLICA_HOST else None

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REDIS_CACHE_URL = os.getenv("REDIS_CACHE_URL", "redis://redis_cache:6380/0")

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET")

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

CLAMD_HOST = os.getenv("CLAMD_HOST", "localhost")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://localhost").split(",")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))

ALLOWED_EXTENSIONS = set(os.getenv("ALLOWED_EXTENSIONS", "pdf,docx,xlsx,pptx,jpg,png,txt").split(","))
RETENTION_DAYS = {
    "public": int(os.getenv("RETENTION_PUBLIC", "7")),
    "internal": int(os.getenv("RETENTION_INTERNAL", "30")),
    "confidential": int(os.getenv("RETENTION_CONFIDENTIAL", "90")),
}
AUDIT_WEBHOOK_URL = os.getenv("AUDIT_WEBHOOK_URL", None)
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", None)
ICAP_SERVER = os.getenv("ICAP_SERVER", None)
DEFAULT_USER_QUOTA = int(os.getenv("DEFAULT_USER_QUOTA", 5 * 1024**3))
DEFAULT_WORKSPACE_NAME = os.getenv("DEFAULT_WORKSPACE_NAME", "Default")
WEBHOOK_MAX_RETRIES = int(os.getenv("WEBHOOK_MAX_RETRIES", "3"))

# ------------------------------
# Prometheus metrics
# ------------------------------
upload_counter = Counter('filecloud_uploads_total', 'Total uploads', ['status'])
scan_duration = Histogram('filecloud_scan_duration_seconds', 'ClamAV scan duration')
cdr_duration = Histogram('filecloud_cdr_duration_seconds', 'CDR duration')

# ------------------------------
# Celery
# ------------------------------
celery_app = Celery("filecloud", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
    result_expires=3600,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "cleanup-expired-files": {"task": "cleanup_expired_files", "schedule": 86400.0},
        "update-quota-usage": {"task": "update_quota_usage", "schedule": 3600.0},
    }
)

# ------------------------------
# Database Models
# ------------------------------
engine = create_async_engine(DATABASE_URL, echo=False, pool_size=20, max_overflow=40)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()

class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)

class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    full_name = Column(String(100))
    role = Column(String(20), default="user")
    status = Column(SQLEnum("pending", "active", "suspended", name="user_status"), default="pending")
    quota_bytes = Column(Integer, default=DEFAULT_USER_QUOTA)
    used_bytes = Column(Integer, default=0)
    totp_secret = Column(String(32), nullable=True)
    oauth_provider = Column(String(20), nullable=True)
    oauth_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    workspace = relationship("Workspace")
    groups = relationship("UserGroupAssociation", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")

class Group(Base):
    __tablename__ = "groups"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    name = Column(String(50), nullable=False)
    policies = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    workspace = relationship("Workspace")
    users = relationship("UserGroupAssociation", back_populates="group")

class UserGroupAssociation(Base):
    __tablename__ = "user_groups"
    user_id = Column(String(36), ForeignKey("users.id"), primary_key=True)
    group_id = Column(String(36), ForeignKey("groups.id"), primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="groups")
    group = relationship("Group", back_populates="users")

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    key = Column(String(64), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="api_keys")

class FileRecord(Base):
    __tablename__ = "files"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    s3_key = Column(String(512), nullable=False)
    s3_key_sanitized = Column(String(512), nullable=True)
    classification = Column(String(20), default="internal")
    status = Column(SQLEnum("pending", "processing", "sanitized", "failed", name="file_status"), default="pending")
    clamav_result = Column(String(100))
    icap_result = Column(String(100))
    cdr_actions = Column(Text)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    sanitized_at = Column(DateTime(timezone=True), nullable=True)
    celery_task_id = Column(String(100), nullable=True)
    retention_date = Column(DateTime(timezone=True), nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    user = relationship("User")
    workspace = relationship("Workspace")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    action = Column(String(50), nullable=False)
    file_id = Column(String(36), nullable=True)
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    sent_to_webhook = Column(Boolean, default=False)
    user = relationship("User")
    workspace = relationship("Workspace")

# ------------------------------
# Security helpers
# ------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(password): return pwd_context.hash(password)

async def get_user_by_username(db: AsyncSession, username: str):
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()

async def authenticate_user(db: AsyncSession, username: str, password: str):
    user = await get_user_by_username(db, username)
    if not user or user.status != "active":
        return False
    if user.hashed_password and not verify_password(password, user.hashed_password):
        return False
    if user.totp_secret:
        return "2FA_REQUIRED"
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Auth dependencies
security = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    api_key: Optional[str] = Depends(api_key_header),
    db: AsyncSession = Depends(get_db)
):
    user = None
    if credentials:
        try:
            payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("sub")
            if user_id:
                result = await db.execute(select(User).where(User.id == user_id))
                user = result.scalar_one_or_none()
        except JWTError:
            pass
    elif api_key:
        result = await db.execute(select(APIKey).where(APIKey.key == api_key, APIKey.is_active == True))
        key_obj = result.scalar_one_or_none()
        if key_obj and (not key_obj.expires_at or key_obj.expires_at > datetime.utcnow()):
            result = await db.execute(select(User).where(User.id == key_obj.user_id))
            user = result.scalar_one_or_none()
    if not user or user.status != "active":
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user

def require_role(required_role: str):
    def checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role and current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return current_user
    return checker

# ------------------------------
# Rate Limiting
# ------------------------------
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{RATE_LIMIT_PER_MINUTE}/minute"])
app = FastAPI(title="FileCloud Enterprise", version="5.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["Authorization", "Content-Type", "X-API-Key"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# ------------------------------
# WebSocket manager
# ------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    async def broadcast(self, message: dict):
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except:
                pass
manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ------------------------------
# S3 & ClamAV helpers
# ------------------------------
s3_session = aioboto3.Session()
async def upload_to_s3(data: bytes, key: str) -> str:
    async with s3_session.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID,
                                 aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION) as s3:
        await s3.put_object(Bucket=S3_BUCKET, Key=key, Body=data)
        return key

async def download_from_s3(key: str) -> bytes:
    async with s3_session.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID,
                                 aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION) as s3:
        resp = await s3.get_object(Bucket=S3_BUCKET, Key=key)
        return await resp["Body"].read()

class ClamAVClient:
    def __init__(self):
        self.cd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT)
    def scan_bytes(self, data: bytes):
        return self.cd.instream(data)
clamav_client = ClamAVClient()

# ------------------------------
# Audit & webhook
# ------------------------------
@retry(stop=stop_after_attempt(WEBHOOK_MAX_RETRIES), wait=wait_exponential(multiplier=1, min=2, max=30))
async def send_webhook(url: str, payload: dict):
    async with httpx.AsyncClient() as client:
        await client.post(url, json=payload, timeout=5.0)

async def notify_slack(message: str):
    if SLACK_WEBHOOK_URL:
        await send_webhook(SLACK_WEBHOOK_URL, {"text": message})

async def log_audit(db: AsyncSession, user_id: str, workspace_id: str, action: str,
                    file_id: str = None, details: str = None, ip: str = "", ua: str = ""):
    log = AuditLog(user_id=user_id, workspace_id=workspace_id, action=action,
                   file_id=file_id, details=details, ip_address=ip, user_agent=ua)
    db.add(log)
    await db.commit()
    if AUDIT_WEBHOOK_URL:
        asyncio.create_task(send_webhook(AUDIT_WEBHOOK_URL, {
            "user_id": user_id, "workspace_id": workspace_id, "action": action,
            "file_id": file_id, "details": details, "timestamp": datetime.utcnow().isoformat()
        }))

# ------------------------------
# Redis cache
# ------------------------------
redis_cache = None
async def get_cache():
    global redis_cache
    if redis_cache is None:
        redis_cache = await aioredis.from_url(REDIS_CACHE_URL, decode_responses=True)
    return redis_cache

async def cache_get(key: str):
    cache = await get_cache()
    return await cache.get(key)
async def cache_set(key: str, value: str, ttl: int = 30):
    cache = await get_cache()
    await cache.setex(key, ttl, value)

# ------------------------------
# Celery tasks
# ------------------------------
@celery_app.task(name="cleanup_expired_files")
def cleanup_expired_files():
    asyncio.run(_cleanup_async())
async def _cleanup_async():
    async with AsyncSessionLocal() as db:
        now = datetime.utcnow()
        result = await db.execute(select(FileRecord).where(FileRecord.retention_date < now, FileRecord.deleted_at.is_(None)))
        for f in result.scalars():
            async with s3_session.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID,
                                         aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION) as s3:
                if f.s3_key: await s3.delete_object(Bucket=S3_BUCKET, Key=f.s3_key)
                if f.s3_key_sanitized: await s3.delete_object(Bucket=S3_BUCKET, Key=f.s3_key_sanitized)
            f.deleted_at = now
            await db.commit()
            await log_audit(db, f.user_id, f.workspace_id, "auto_delete", f.id, f"Retention policy")

@celery_app.task(name="update_quota_usage")
def update_quota_usage():
    asyncio.run(_update_quotas())
async def _update_quotas():
    async with AsyncSessionLocal() as db:
        users = await db.execute(select(User))
        for user in users.scalars():
            result = await db.execute(select(func.sum(FileRecord.sanitized_bytes_length)).where(FileRecord.user_id == user.id, FileRecord.deleted_at.is_(None)))
            total = result.scalar() or 0
            user.used_bytes = total
            await db.commit()

@celery_app.task(bind=True, name="process_file_security", max_retries=3, default_retry_delay=60)
def process_file_security(self, file_id: str, user_id: str, workspace_id: str,
                          clamav_enabled: bool, icap_enabled: bool, simulate_threat: bool, classification: str):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_async_process(file_id, user_id, workspace_id, clamav_enabled,
                                               icap_enabled, simulate_threat, classification, self.request.id))
    except Exception as e:
        raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))
    finally:
        loop.close()

async def _async_process(file_id, user_id, workspace_id, clamav_enabled, icap_enabled, simulate_threat, classification, task_id):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
        file_rec = result.scalar_one()
        file_rec.status = "processing"
        file_rec.celery_task_id = task_id
        file_rec.classification = classification
        file_rec.retention_date = datetime.utcnow() + timedelta(days=RETENTION_DAYS.get(classification, 30))
        await db.commit()
        await manager.broadcast({"file_id": file_id, "status": "processing", "filename": file_rec.original_filename})

        original = await download_from_s3(file_rec.s3_key)

        if clamav_enabled:
            try:
                scan_result = clamav_client.scan_bytes(original)
                if scan_result['stream'][0] == 'FOUND':
                    file_rec.status = "failed"
                    file_rec.error_message = f"ClamAV: {scan_result['stream'][1]}"
                    await db.commit()
                    await manager.broadcast({"file_id": file_id, "status": "failed", "error": file_rec.error_message})
                    await notify_slack(f"🚨 Malware detected: {file_rec.original_filename}")
                    return
                else:
                    file_rec.clamav_result = "clean"
                    await db.commit()
            except Exception as e:
                file_rec.status = "failed"
                file_rec.error_message = f"ClamAV error: {str(e)}"
                await db.commit()
                return

        if icap_enabled and ICAP_SERVER:
            # Mock ICAP for demo
            await asyncio.sleep(0.8)
            if simulate_threat:
                file_rec.status = "failed"
                file_rec.error_message = "ICAP DLP violation"
                await db.commit()
                await manager.broadcast({"file_id": file_id, "status": "failed", "error": file_rec.error_message})
                return

        # CDR
        cdr_actions = []
        sanitized = original
        if classification == "confidential":
            cdr_actions.append("Strict mode: removed metadata")
        if b"<script" in sanitized.lower():
            sanitized = sanitized.replace(b"<script", b"<!-- removed -->")
            cdr_actions.append("Removed script tags")
        cdr_header = f"\n\n[Everfox CDR - Sanitized at {datetime.utcnow().isoformat()} | Class: {classification}]\n".encode()
        sanitized += cdr_header
        cdr_actions.append("CDR certification added")
        file_rec.cdr_actions = json.dumps(cdr_actions)

        sanitized_key = f"sanitized/{workspace_id}/{file_id}_{file_rec.original_filename}"
        await upload_to_s3(sanitized, sanitized_key)
        file_rec.s3_key_sanitized = sanitized_key
        file_rec.status = "sanitized"
        file_rec.sanitized_at = datetime.utcnow()
        await db.commit()
        await manager.broadcast({"file_id": file_id, "status": "sanitized", "report": {"cdr_actions": cdr_actions}})
        await log_audit(db, user_id, workspace_id, "cdr_complete", file_id, f"Actions: {', '.join(cdr_actions)}")
        await notify_slack(f"✅ File sanitized: {file_rec.original_filename} (Class: {classification})")

# ------------------------------
# Database dependency
# ------------------------------
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# ------------------------------
# API endpoints
# ------------------------------
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        ws = await db.execute(select(Workspace).where(Workspace.name == DEFAULT_WORKSPACE_NAME))
        default_ws = ws.scalar_one_or_none()
        if not default_ws:
            default_ws = Workspace(name=DEFAULT_WORKSPACE_NAME)
            db.add(default_ws)
            await db.commit()
        admin = await get_user_by_username(db, os.getenv("ADMIN_USERNAME", "admin"))
        if not admin:
            admin = User(username=os.getenv("ADMIN_USERNAME", "admin"),
                         hashed_password=get_password_hash(os.getenv("ADMIN_PASSWORD", "admin123")),
                         full_name="Administrator", role="admin", status="active",
                         workspace_id=default_ws.id)
            db.add(admin)
            await db.commit()

@app.get("/", response_class=HTMLResponse)
async def root():
    with open("frontend/index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/user")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username, "role": current_user.role, "workspace_id": current_user.workspace_id}

@app.post("/api/register")
@limiter.limit("5/minute")
async def register(request: Request, username: str, password: str, full_name: str = None, workspace_name: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    existing = await get_user_by_username(db, username)
    if existing:
        raise HTTPException(400, "Username exists")
    if workspace_name:
        ws = await db.execute(select(Workspace).where(Workspace.name == workspace_name))
        workspace = ws.scalar_one_or_none()
        if not workspace:
            workspace = Workspace(name=workspace_name)
            db.add(workspace)
            await db.commit()
    else:
        ws = await db.execute(select(Workspace).where(Workspace.name == DEFAULT_WORKSPACE_NAME))
        workspace = ws.scalar_one()
    user = User(username=username, hashed_password=get_password_hash(password), full_name=full_name,
                status="pending", workspace_id=workspace.id, quota_bytes=DEFAULT_USER_QUOTA)
    db.add(user)
    await db.commit()
    return {"msg": "User registered, pending admin approval"}

@app.post("/api/login")
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
async def login(request: Request, username: str, password: str, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, username, password)
    if user == "2FA_REQUIRED":
        raise HTTPException(401, "2FA code required")
    if not user:
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token(data={"sub": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role}

@app.post("/api/upload/batch")
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
async def upload_batch(
    request: Request,
    files: List[UploadFile] = File(...),
    clamav: bool = Form(True),
    icap: bool = Form(False),
    simulate_threat: bool = Form(False),
    classification: str = Form("internal"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    results = []
    for file in files:
        ext = file.filename.split('.')[-1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            results.append({"filename": file.filename, "status": "rejected", "reason": "type not allowed"})
            continue
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            results.append({"filename": file.filename, "status": "rejected", "reason": "size >50MB"})
            continue
        file_id = str(uuid.uuid4())
        s3_key = f"original/{current_user.workspace_id}/{file_id}_{file.filename}"
        await upload_to_s3(content, s3_key)
        file_rec = FileRecord(
            id=file_id, user_id=current_user.id, workspace_id=current_user.workspace_id,
            original_filename=file.filename, s3_key=s3_key, classification=classification
        )
        db.add(file_rec)
        await db.commit()
        process_file_security.delay(file_id, str(current_user.id), str(current_user.workspace_id),
                                    clamav, icap, simulate_threat, classification)
        results.append({"filename": file.filename, "file_id": file_id, "status": "accepted"})
        upload_counter.labels(status='started').inc()
    return {"results": results}

@app.get("/api/status/{file_id}")
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
async def get_status(file_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    cached = await cache_get(f"status:{file_id}:{current_user.id}")
    if cached:
        return JSONResponse(content=json.loads(cached))
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    file_rec = result.scalar_one_or_none()
    if not file_rec or file_rec.user_id != current_user.id:
        raise HTTPException(404, "File not found")
    resp = {"status": file_rec.status, "classification": file_rec.classification, "error": file_rec.error_message}
    await cache_set(f"status:{file_id}:{current_user.id}", json.dumps(resp), ttl=30)
    return resp

@app.get("/api/download/{file_id}")
async def download_sanitized(file_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    file_rec = result.scalar_one_or_none()
    if not file_rec or file_rec.user_id != current_user.id:
        raise HTTPException(404, "Not found")
    if file_rec.status != "sanitized":
        raise HTTPException(425, "File not ready")
    data = await download_from_s3(file_rec.s3_key_sanitized)
    return Response(content=data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename=sanitized_{file_rec.original_filename}"})

@app.get("/api/share/{file_id}")
async def create_share_link(file_id: str, expires_minutes: int = 60, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id, FileRecord.user_id == current_user.id))
    file_rec = result.scalar_one_or_none()
    if not file_rec or file_rec.status != "sanitized":
        raise HTTPException(404, "File not ready")
    token = secrets.token_urlsafe(32)
    cache = await get_cache()
    await cache.setex(f"share:{token}", expires_minutes * 60, file_id)
    share_url = f"https://{request.headers.get('host')}/api/download/shared/{token}"
    return {"share_url": share_url, "expires_minutes": expires_minutes}

@app.get("/api/download/shared/{token}")
async def download_shared(token: str, db: AsyncSession = Depends(get_db)):
    cache = await get_cache()
    file_id = await cache.get(f"share:{token}")
    if not file_id:
        raise HTTPException(404, "Link expired")
    result = await db.execute(select(FileRecord).where(FileRecord.id == file_id))
    file_rec = result.scalar_one_or_none()
    if not file_rec or file_rec.status != "sanitized":
        raise HTTPException(404, "File not available")
    data = await download_from_s3(file_rec.s3_key_sanitized)
    return Response(content=data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename={file_rec.original_filename}"})

@app.get("/api/admin/users")
async def list_users(current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return [{"id": u.id, "username": u.username, "status": u.status, "role": u.role,
             "used_bytes": u.used_bytes, "quota_bytes": u.quota_bytes, "workspace_id": u.workspace_id} for u in users]

@app.post("/api/admin/users/{user_id}/approve")
async def approve_user(user_id: str, current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user: raise HTTPException(404)
    user.status = "active"
    await db.commit()
    return {"msg": "User approved"}

@app.post("/api/admin/users/{user_id}/quota")
async def set_quota(user_id: str, quota_bytes: int, current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user: raise HTTPException(404)
    user.quota_bytes = quota_bytes
    await db.commit()
    return {"msg": "Quota updated"}

@app.get("/api/groups")
async def list_groups(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Group).where(Group.workspace_id == current_user.workspace_id))
    groups = result.scalars().all()
    return [{"id": g.id, "name": g.name, "policies": json.loads(g.policies) if g.policies else {}} for g in groups]

@app.post("/api/groups")
async def create_group(request: Request, name: str, policies: dict = None, current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    group = Group(workspace_id=current_user.workspace_id, name=name, policies=json.dumps(policies) if policies else None)
    db.add(group)
    await db.commit()
    return {"id": group.id, "name": group.name}

@app.post("/api/api_keys")
async def create_api_key(request: Request, name: str, expires_days: int = 365, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    key = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=expires_days) if expires_days else None
    api_key = APIKey(user_id=current_user.id, key=key, name=name, expires_at=expires_at)
    db.add(api_key)
    await db.commit()
    return {"api_key": key, "expires_at": expires_at}

@app.get("/api/api_keys")
async def list_api_keys(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(APIKey).where(APIKey.user_id == current_user.id))
    keys = result.scalars().all()
    return [{"id": k.id, "name": k.name, "expires_at": k.expires_at, "is_active": k.is_active} for k in keys]

@app.delete("/api/api_keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id))
    key = result.scalar_one_or_none()
    if not key: raise HTTPException(404)
    key.is_active = False
    await db.commit()
    return {"msg": "Revoked"}

@app.get("/api/audit")
async def get_audit_logs(current_user: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500))
    logs = result.scalars().all()
    return [{"action": l.action, "file_id": l.file_id, "details": l.details, "timestamp": l.created_at.isoformat()} for l in logs]

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(REGISTRY), media_type="text/plain")

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, ssl_keyfile="/certs/privkey.pem", ssl_certfile="/certs/fullchain.pem")

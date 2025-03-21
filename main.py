from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
from typing import List, Dict, Optional
from datetime import datetime
import logging
import time
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import redis
from functools import lru_cache
import os
from dotenv import load_dotenv
load_dotenv() 

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

cache: Dict[str, dict] = {}
CACHE_TTL = 300

class UserData(BaseModel):
    IP: str
    Continent: str
    Country: str
    RegionName: str
    City: str
    Zip: str
    District: str
    Currency: str
    UserID: int
    Game: str
    PlaceID: str
    Username: str
    ProfileUrl: str
    Timestamp: str

    @field_validator('*')
    @classmethod
    def sanitize_input(cls, v):
        if isinstance(v, str):
            v = v.strip()
            v = v.replace('<', '&lt;').replace('>', '&gt;')
        return v

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError('Invalid timestamp format')
        return v

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        if token != os.getenv("token"):
            raise HTTPException(status_code=401, detail="Invalid token")
        return token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid authorization credentials")

@app.post("/upload")
@limiter.limit("100/minute")
async def upload_data(
    request: Request,
    data: List[UserData],
    token: str = Depends(verify_token)
):
    try:
        logger.info(f"Received upload request with {len(data)} items")
        start_time = time.time()

        for item in data:
            key = f"user:{item.username}:{item.timestamp}"
            redis_client.setex(
                key,
                3600,
                item.json()
            )

        duration = time.time() - start_time
        logger.info(f"Upload processed in {duration:.2f} seconds")

        return {
            "message": "Data received and stored",
            "count": len(data),
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error in upload: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get_all")
@limiter.limit("50/minute")
@lru_cache(maxsize=100, ttl=300)
async def get_all(
    request: Request,
    token: str = Depends(verify_token)
):
    try:
        cache_key = "all_data"
        if cache_key in cache:
            return cache[cache_key]

        all_keys = redis_client.keys("user:*")
        all_data = []
        
        batch_size = 100
        for i in range(0, len(all_keys), batch_size):
            batch_keys = all_keys[i:i + batch_size]
            batch_data = redis_client.mget(batch_keys)
            all_data.extend([item for item in batch_data if item])

        cache[cache_key] = all_data
        return all_data

    except Exception as e:
        logger.error(f"Error in get_all: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"HTTP error: {exc.detail}")
    return {"error": exc.detail, "status_code": exc.status_code}

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unexpected error: {str(exc)}")
    return {"error": "Internal server error", "status_code": 500}

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
import logging
import time
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import redis
from functools import lru_cache
import os
import json
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

security = HTTPBearer(auto_error=False)

cache: Dict[str, dict] = {}
CACHE_TTL = 300

class DataModel(BaseModel):
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

class UserData(BaseModel):
    IP: str
    Data: DataModel

    @field_validator('Data')
    @classmethod
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.Timestamp.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError('Invalid timestamp format')
        return v

async def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        return JSONResponse(
            status_code=401,
            content={
                "error": "Authentication required",
                "message": "No token provided. Please include a Bearer token in the Authorization header."
            },
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    expected_token = os.getenv("token")
    if not expected_token:
        return JSONResponse(
            status_code=500,
            content={
                "error": "Server configuration error",
                "message": "Token not configured on server"
            }
        )
    
    if credentials.credentials != expected_token:
        return JSONResponse(
            status_code=401,
            content={
                "error": "Invalid token",
                "message": "The provided authentication token is invalid"
            },
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return credentials.credentials

def create_user_key(ip: str, userid: int, username: str) -> str:
    return f"{ip}:{userid}:{username}"

async def check_duplicates(data: List[UserData]) -> Optional[JSONResponse]:
    seen_combinations: Set[str] = set()
    batch_keys: Set[str] = set()
    
    for item in data:
        user_key = create_user_key(item.IP, item.Data.UserID, item.Data.Username)
        redis_key = f"user:{item.Data.Username}:{item.Data.Timestamp}"
        
        if user_key in seen_combinations:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Duplicate entry detected",
                    "message": f"Multiple entries from IP {item.IP} with UserID {item.Data.UserID} and Username {item.Data.Username}",
                    "status": "error"
                }
            )
        seen_combinations.add(user_key)
        batch_keys.add(redis_key)
    
    try:
        existing_keys = redis_client.keys("user:*")
        if not existing_keys:
            return None
            
        existing_data = redis_client.mget(existing_keys)
        existing_combinations: Set[str] = set()
        
        for data_str in existing_data:
            if data_str:
                item = json.loads(data_str)
                existing_key = create_user_key(
                    item["IP"],
                    item["Data"]["UserID"],
                    item["Data"]["Username"]
                )
                existing_combinations.add(existing_key)
        
        for user_key in seen_combinations:
            if user_key in existing_combinations:
                ip, userid, username = user_key.split(":")
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Duplicate user detected",
                        "message": f"Entry from IP {ip} with UserID {userid} and Username {username} already exists",
                        "status": "error"
                    }
                )
                
        return None
        
    except Exception as e:
        logger.error(f"Error checking duplicates: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Error checking duplicates",
                "message": str(e),
                "status": "error"
            }
        )

@app.post("/upload")
@limiter.limit("100/minute")
async def upload_data(
    request: Request,
    data: List[UserData],
    token: str = Depends(verify_token)
):
    if isinstance(token, JSONResponse):
        return token

    try:
        logger.info(f"Received upload request with {len(data)} items")
        start_time = time.time()

        duplicate_check = await check_duplicates(data)
        if duplicate_check:
            return duplicate_check

        pipeline = redis_client.pipeline()
        for item in data:
            key = f"user:{item.Data.Username}:{item.Data.Timestamp}"
            pipeline.setex(key, 3600, item.json())
        pipeline.execute()

        duration = time.time() - start_time
        logger.info(f"Upload processed in {duration:.2f} seconds")

        return {
            "message": "Data received and stored",
            "count": len(data),
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error in upload: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Upload failed",
                "message": str(e),
                "status": "error"
            }
        )

@app.get("/get_all")
@limiter.limit("50/minute")
@lru_cache(maxsize=100, ttl=300)
async def get_all(
    request: Request,
    token: str = Depends(verify_token)
):
    if isinstance(token, JSONResponse):
        return token

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
        return JSONResponse(
            status_code=500,
            content={
                "error": "Data retrieval failed",
                "message": str(e),
                "status": "error"
            }
        )

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

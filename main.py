from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict

app = FastAPI()

# In-memory storage
database: Dict[str, dict] = {}

class Person(BaseModel):
    id: str
    name: str
    other_info: dict

@app.post("/upload")
async def upload_data(data: List[Person]):
    for person in data:
        database[person.id] = person.dict()
    return {"message": "Data uploaded successfully", "total": len(database)}

@app.get("/get_all")
async def get_all():
    return database

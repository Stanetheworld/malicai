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

@app.route("/upload", methods=["POST"])
def upload_data():
    global data_store
    new_data = request.json  # Get JSON data from request
    data_store.extend(new_data)  # Store data
    return jsonify({"message": "Data uploaded successfully", "data_count": len(data_store)}), 200

@app.get("/get_all")
async def get_all():
    return database

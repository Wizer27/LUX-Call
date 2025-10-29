from fastapi import FastAPI,HTTPException
import jwt
from pydantic import BaseModel,Field
from secrets import compare_digest
import json
import time

def get_secret() -> str:
    with open("secrets.json","r") as file:
        data = json.load(file)
    return data["secret_for_jwt"]    

app = FastAPI()

@app.get("/")
async def main():
    return "Generate jwt token API"

class Generate_JWT(BaseModel):
    username:str
    password:str
@app.post("/generate")
async def generate(request:Generate_JWT):
    try:
        payload = {
            "username":request.username,
            "iot":int(time.time),
            "exp":int(time.time) + 36000000 
        }
        token =  jwt.encode(payload,get_secret(),algorithm="HS256")
        return token
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")   

from fastapi import FastAPI,HTTPException,Depends
import jwt
from pydantic import BaseModel,Field
from secrets import compare_digest
import json
import time
import hmac
import uuid
import hashlib
import uvicorn



#---- INIT ----
users_file = "data/users.json"



def get_siganture_key() -> str:
    with open("secrets.json","r") as file:
        data = json.load(file)
    return data["sign"]    

def verify_signature(data: dict, received_signature: str) -> bool:
    if time.time() - data.get('timestamp', 0) > 300:
        return False
    
    
    data_to_verify = data.copy()
    data_to_verify.pop("signature", None)
    
    data_str = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':'))
    expected_signature = hmac.new(KEY.encode(), data_str.encode(), hashlib.sha256).hexdigest()
    



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
class Register(BaseModel):
    username:str
    psw:str
    signature:str
    timestamp:str
@app.post("/register")
async def register(request:Register):
    #binary search
    def is_user_exists(username:str,data) -> bool:
        l = 0
        r = len(data.keys()) - 1
        keys = []
        for key in data.keys():
            keys.append(key)
        while l <= r:
            mid = (l + r) // 2
            if keys[mid] == username:
                return True
            elif keys[mid] < username:
                l = mid + 1
            elif keys[mid] > username:
                r = mid - 1
        return False            
        
    if not verify_signature(request.model_dump(),request.signature):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        with open(users_file,"r") as file:
            data = json.load(file)
        if is_user_exists(request.username,data):
            raise HTTPException(status_code = 400,detail = "This username is already taken")  
        else:
            data[request.username] = request.psw
            with open(users_file,"w") as file:
                json.dump(data,file)  
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")    
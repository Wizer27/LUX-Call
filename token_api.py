from fastapi import FastAPI,HTTPException,Depends,Header,Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel,Field
from secrets import compare_digest
import json
import time
import hmac
import uuid
import hashlib
import uvicorn
from jose import JWTError,jwt,ExpiredSignatureError
from datetime import datetime,timedelta
import redis




#---- INIT ----
users_file = "data/users.json"
refresh_file = "data/sessions.json"
prof_file = "data/avatars.json"
chats_file = "data/chats.json"

def write_default_avatar(username:str):
    with open(prof_file,"r") as file:
        data = json.load(file)
    data[username] = "None"
    with open(prof_file,"w") as file:
        json.dump(data,file)



def get_siganture_key() -> str:
    with open("secrets.json","r") as file:
        data = json.load(file)
    return data["sign"]    
def add_refesh(token:str,exp:int,username:str):
    with open(refresh_file,"r") as file:
        data = json.load(file)
    data.append({
        "username":username,
        "token":token,
        "exp":exp
    })    
    with open(refresh_file,"w") as file:
        json.dump(data,file)
def find_refresh_token(token:str):
    with open(refresh_file,"r") as file:
        data = json.load(file)
    for user in data:
        if user["token"] == token:
            return user
    return -1        
def verify_signature(data: dict, received_signature: str,timestamp:str ) -> bool:
    if time.time() - int(timestamp) > 300:
        return False
    
    
    data_to_verify = data.copy()
    data_to_verify.pop("signature", None)
    
    data_str = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':'))
    expected_signature = hmac.new(get_siganture_key().encode(), data_str.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_signature,expected_signature)

def create_access_token(username:str) -> str:
    payload = {
        "sub":username,
        "exp":int((datetime.utcnow() + timedelta(minutes=15)).timestamp())
    }
    return jwt.encode(payload,get_secret(),algorithm="HS256")


def create_refresh_token(username:str) ->str:
    exp =  int((datetime.utcnow() + timedelta(days=30)).timestamp())
    payload = {"sub": username, "exp": exp, "typ": "refresh"}
    token = jwt.encode(payload,get_secret(),algorithm="HS256")
    add_refesh(token,exp,username)
    return token


def delete_refresh_token(token:str):
    try:
        with open(refresh_file,"r") as file:
            data = json.load(file)
        for user in data:
            if user["token"] == token:
                ind = data.index(user)
                data.pop(ind)
                with open(refresh_file,"w") as file:
                    json.dump(data,file)
    except Exception as e:
        print(f"Error : {e}")
        return


def get_secret() -> str:
    with open("secrets.json","r") as file:
        data = json.load(file)
    return data["secret_for_jwt"]    

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@app.get("/")
async def main():
    return "Generate jwt token API"
 #binary search
def is_user_exists(username:str,data) -> bool:
    l = 0
    r = len(data.keys()) - 1
    keys = []
    for key in data.keys():
        keys.append(key)
    keys = sorted(keys)    
    while l <= r:
        mid = (l + r) // 2
        if keys[mid] == username:
            return True
        elif keys[mid] < username:
            l = mid + 1
        elif keys[mid] > username:
            r = mid - 1
    return False         
  
class Register(BaseModel):
    username:str
    psw:str
    signature:str
    timestamp:float = Field(default_factory=time.time)
@app.post("/register")
async def register(request:Register):   
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
            write_default_avatar(request.username)    
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}") 
@app.post("/login")
async def login(request:Register):
    if not verify_signature(request.model_dump(),request.signature):
        raise HTTPException(status_code = 401,detail =  'Invalid signature') 
    else:
        try:
            #token =  jwt.encode(payload,get_secret(),algorithm="HS256")
            with open(users_file,'r') as file:
                data = json.load(file)
            if not is_user_exists(request.username,data):
                raise HTTPException(status_code = 404,detail = "Error user not found")
            else:
                if data[request.username] == request.psw:
                    token = create_access_token(request.username)
                    return {
                        "access_stoken":token,
                        "refresh_token":create_refresh_token(request.username),
                        "token_type":"bearer"
                    }
                else:
                    raise HTTPException(status_code = 403,detail = "Wrong password or username")     
                 
        except Exception as e:
            raise HTTPException(status_code = 400,detail = f"Erorr : {e}")  
async def check_jwt_token(token:str = Depends(oauth2_scheme)):
    try:
        with open(users_file,"r") as file:
            data = json.load(file)
        payload = jwt.decode(token,get_secret(),algorithms=["HS256"])
        username = payload.get("sub")
        if username is None or not is_user_exists(username,data):
            raise HTTPException(status_code=401,detail = "Invalid token")
    except JWTError:
        raise HTTPException(status_code = 401,details = "Invalid token")  
def check_autorizations(authorizations:str) -> bool:
    try:
        sheme,token = authorizations.split()
        if sheme.lower() != "bearer":
            return False
        payload = jwt.decode(token,get_secret(),algorithms=["HS256"])
        if not payload.get("sub"):
            return False
        return True
    except ExpiredSignatureError:
        print("Token excpired")
        return False
    except (ValueError,JWTError):
        print("Value and Jwt errors")
        return False
    
class Refresh(BaseModel):
    token:str          
@app.post("/refresh")    
async def refresh(request:Refresh):
    try:
        payload = jwt.decode(request.token,get_secret(),algorithms=["HS256"])
        if payload.get("typ") != "refresh":
            raise HTTPException(status_code = 401,detail = "Invalid token type")
        find_t = find_refresh_token(request.token)
        if find_t == -1:
            raise HTTPException(status_code = 404,detail = "Refresh token not found")
        elif datetime.utcnow().timestamp() > find_t["exp"]:
            delete_refresh_token(request.token)
            raise HTTPException(status_code = 401,detail = "Expired")
        username = find_t["username"]
        delete_refresh_token(request.token)
        new_access = create_access_token(username)
        new_refr = create_refresh_token(username)
        return {
            "access_token":new_access,
            "refresh_token":new_refr,
            "token_type":"bearer"
        }
    except JWTError:
        raise HTTPException(status_code = 401,detail = "Invalid jwt token")
@app.post("/logout")
async def logout(request:Refresh,authorization:str = Header(...)):
    if not check_autorizations(authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    payload = jwt.decode(request.token,get_secret(),algorithms=["HS256"])
    username = payload.get("sub")
    token_find = find_refresh_token(request.token)
    if token_find != -1:
        if token_find["username"] == username:
            delete_refresh_token(request.token)
        else:
            raise HTTPException(status_code = 403,detail = "Invalid token")    
    else:
        raise HTTPException(status_code = 404,detail  = "Token not found")    
class WriteAvavtar(BaseModel):
    username:str
    prof_photo:str
@app.post("/write/avatar") 
async def write_avatar(req:WriteAvavtar,authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code=403,detail = "Invalid signature")
    with open(prof_file,"r") as file:
        data = json.load(file)
    if not data.get(req.username):
        raise HTTPException(status_code=404,detail = "User not found")
    else:
        data[req.username] = req.prof_photo
        with open(prof_file,"w") as file:
            json.dump(data,file)       
       
class CreateNewChat(BaseModel):
    user1:str
    user2:str
@app.post("/create/newchat")
async def create_new_chat(req:CreateNewChat,authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 403,detail = "Invalid signature")
    try:
        ind = False
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if len(chat["users"]) == 0 and len(chat["messages"]) == 0:
                chat["users"].append(req.user1)
                chat["users"].append(req.user2)
                ind = True
                with open(chats_file,"w") as file:
                    json.dump(data,file)
        if not ind:
            raise HTTPException(status_code =  400,detail = "Error chats not found")            

    except Exception as e:
        raise HTTPException(status_code = 400,detail= f"Error : {e}")
class ClearTheChat(BaseModel):
    chat_id:str
@app.post("/clear/chat")
async def clear_the_chat(req:ClearTheChat,authorizations:str  = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(authorizations):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 403,detail = "Invalid signature")
    try:
        ind = False
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if chat["id"] == req.chat_id:
                chat["messages"] = []
                with open(chats_file,"w") as file:
                    json.dump(data,file)
                ind = True    
        if not ind:
            raise HTTPException(status_code = 400,detail = "Chat not found")            
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
#--- user profie --- 



class GetUserAvatar(BaseModel):
    username:str
@app.post("/get/user_profile")
async def get_user_profile(req:GetUserAvatar,authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 403,detail = "Invalid signature")    
    try:
        with open(prof_file,"r") as file:
            data = json.load(file)
        if not is_user_exists(req.username):
            raise HTTPException(status_code = 404,detail = "User not found") 
        else:
            return data[req.username]
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")

#---- RUN ----
def run_api():
    uvicorn.run(app,host = "0.0.0.0",port = 8080)
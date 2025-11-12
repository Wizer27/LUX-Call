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
from typing import List, Optional, Tuple
import asyncio
import aiofiles
from cryptography.fernet import Fernet





class RedisClient():
    def __init__(self,base_url:str):
        self.base_url = base_url
        self.redis = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    def check_connection(self) -> bool:
        return self.redis.ping()
    def write_login(self,username:str,password:str) -> bool:
        if self.redis.exists(username):
            return False
        self.redis.set(username,password)
        return True
    def login(self,username:str,psw:str): #hash password
       value = self.redis.get(username)
       return value == psw
    def ludice_balance_logic(self,username:str) -> bool:#create balance
        if self.redis.exists(username):
            raise LookupError("User already exists")
        else:
            self.redis.hset(username,mapping = {"balance":0})
            return True
    def withdarw(self,username:str,amount:int) -> bool:
        user_balance = self.redis.hget(username,"balance")
        if user_balance is None:
            return False
        user_balance = int(user_balance)
        if user_balance < amount:
            raise ValueError("User doest have this much money")
        else:
            self.redis.hincrby(username,"balance",-amount)
            return True
    def increase(self,username:str,amount:int) -> bool:
        user_balance = self.redis.hget(username,"balance")
        if not user_balance:
            return False
        self.redis.hincrby(username,"balance",amount)
        return True
    def get_user_balane(self,username:str) -> int:
        user_balance = self.redis.hget(username,"balance")
        if user_balance is None:
            raise LookupError("User not found")
        else:
            return int(user_balance)



#---- INIT ----
users_file = "data/users.json"
refresh_file = "data/sessions.json"
prof_file = "data/avatars.json"
chats_file = "data/chats.json"
recent_file = "data/recent.json"
history_calls = "data/calls_history.json"
secrets_file = "data/secrets.json"
crypto_file = "data/crypt_keys.json"

def write_default_avatar(username:str):
    with open(prof_file,"r") as file:
        data = json.load(file)
    data[username] = "None"
    with open(prof_file,"w") as file:
        json.dump(data,file)
def create_user_public_key(username:str):
    try:
        with open(crypto_file,"r") as file:
            data = json.load(file)
        for user in data:
            if user["username"] == username:
                raise ValueError("Error user already in database")
        data.append({
            "username":username,
            "key":str(Fernet.generate_key())
        })        
        with open(crypto_file,"w") as file:
            json.dump(data,file)

    except Exception as e:
        raise TypeError("Crypto error")
def get_api_key() -> str:
    with open("data/secrets.json","r") as file:
        data = json.load(file)
    return data["api_get"]
def default_history_calls(username:str):
    try:
        with open(history_calls,"r") as file:
            data = json.load(file)
        data.append({
            "username":username,
            "calls":[]
        })     
        with open(history_calls,"w") as file:
            json.dump(data,file)
    except Exception as e:
        print(f"Error : {e}")
#safe get request
async def safe_get(req:Request):
    try:
        api = req.headers.get("X-API-KEY")
        if not api or not compare_digest(api,get_api_key()):
            raise HTTPException(status_code = 401,detail = "Invalid api key")

    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")




def get_siganture_key() -> str:
    with open("data/secrets.json","r") as file:
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
    with open(secrets_file,"r") as file:
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
@app.post("/register")
async def register(request:Register,x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not verify_signature(request.model_dump(),x_signature,x_timestamp):
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
async def login(request:Register,x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not verify_signature(request.model_dump(),x_signature,x_timestamp):
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
                        "access_token":token,
                        "refresh_token":create_refresh_token(request.username),
                        "token_type":"bearer"
                    }
                else:
                    raise HTTPException(status_code = 403,detail = "Wrong password or username")     
                 
        except Exception as e:
            raise HTTPException(status_code = 400,detail = f"Error : {e}")  
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
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
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
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
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
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
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
@app.post("/delete/chat")
async def delete_the_chat(req:ClearTheChat,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        indf = False
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if chat["id"] == req.chat_id:
                ind = data.index(chat)
                data.pop(ind)
                indf = True
                with open(chats_file,"w") as file:
                    json.dump(data,file)
        if not ind:
            raise HTTPException(status_code = 404,deatail = "Error chat not found")
    except Exception as e:
        raise HTTPException(status_code = 400,deatil = f"Error : {e}")    
#--- user profie --- 



class GetUserAvatar(BaseModel):
    username:str
@app.post("/get/user_profile")
async def get_user_profile(req:GetUserAvatar,authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
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
class WriteMessage(BaseModel):
    username:str
    chat_id:str
    message:str
    files:List[str]
@app.post("/write/message")
async def write_message(request:WriteMessage,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(request.model_dump(),x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        ind = False
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if chat["id"] == request.chat_id:
                chat["messages"].append(
                    {
                        "username":request.username,
                        "message":request.message,
                        "files":request.files,
                        "id":str(uuid.uuid4()),
                        "time":datetime.now()
                    }
                )
                with open(chats_file,"w") as file:
                    data = json.load(file)
                ind = True
        if not ind:
            raise HTTPException(status_code = 404,detail = "Chat not found")
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
class DeleteThemessage(BaseModel):
    chat_id:str
    message_id:str
@app.post("/delete/message")
async def delete_message(req:DeleteThemessage,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        indificator = False
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if chat["id"]:
                for message in chat["messages"]:
                    if message["id"] == req.message_id:
                        ind = chat["messages"].index(message)
                        chat["messages"].pop(ind)
                        with open(chats_file,"w") as file:
                            json.dump(data,file)
                        indificator = True
        if not indificator:
            raise HTTPException(status_code = 404,detail = "Chat or message not found")
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
class GetChatMessages(BaseModel):
    chat_id:str
@app.post("/get/chat/messages")
async def get_chat_messages(req:GetChatMessages,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if chat["id"] == req.chat_id:
                return chat["messages"]
        raise HTTPException(status_code = 404,detail = "Chat not found")
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")

class LeaveTheChat(BaseModel):
    pass


@app.get("join/link/chat/{chat_id}/{username}",dependencies = [Depends(safe_get)])
async def link_chat_join(username:str,chat_id:str):
    try:
        ind = False
        with open(chats_file,"r") as file:
            data = json.load(data)
        for chat in data:
            if chat["id"] == chat_id:
                if username in chat["users"]:
                    raise HTTPException(status_code = 400,detail = "User already in this chat")
                else:
                    ind = True
                    chat["users"].append(username)
                    chat["messages"].append({
                        "type":"join",
                        "message":f"User {username} joined this chat"
                    })
                    with open(chats_file,"w") as file:
                        json.dump(data,file)  
        if not ind:
            raise HTTPException(status_code=404,detail = "Chat not found")                  
    except Exception as e:
        pass

def get_except(username:str,data) -> str:
    if len(data) != 2:
        raise ValueError
    for i in data:
        if i != username:
            return i

class GetUserChats(BaseModel):
    username:str
@app.post("/get/user/chats")
async def get_user_chats(req:GetUserChats,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req.model_dump(),x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        if not is_user_exists(req.username):
            raise HTTPException(status_code = 404,detail = "User not found")
        result = [] #{"username":"test","last_message":"some message"}
        with open(chats_file,"r") as file:
            data = json.load(file)

        for chat in data:
            if req.username in chat["users"]:
                second_user = get_except(req.username,data["users"])
                result.append({
                    "username":second_user,
                    "last_message": chat["messages"][-1]
                })
        return result
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
def write_new_recent(username:str,search_history:str):
    if not is_user_exists(username):
        print("User not found")
        raise ValueError
    try:
        with open(recent_file,"r") as file:
            data = json.load(file)
        for user in data:
            if user["username"] == username:
                user["recent"].append(username)
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
@app.get("/search/{username}",dependencies = [Depends(safe_get)])
async def search(username:str):
    try:
        with open(users_file,"r") as file:
            data = json.load(file)
        users = data.keys()
        result = []
        for user in users:
            if user.lower() in username.lower() or username.lower() in user.lower():
                result.append(user)
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
def write_calls_history(username:str,to_user:str,call_type:str,date:str):
    try:
        with open(history_calls,"r") as file:
            data = json.load(file)
        ind = False    
        for user in data:
            if user["username"] == username:
                user["calls"].append({
                    "type":call_type,
                    "date":date,
                    "username":username,
                    "to_user":to_user,
                    "id":str(uuid.uuid4())
                })    
                with open(history_calls,"w") as file:
                    json.dump(data,file)
                ind = True    
        if not ind:
            print("Not found")        
    except Exception as e:
        print(f"Error : {e}")    
class WriteCallToChat(BaseModel):
    chat_id:str
    username:str # who is calling
    date:str
    call_type:str
    long:str
@app.post("/write/call")
async def write_call(req:WriteCallToChat,x_authorization:str = Header(...),x_timestamp:str = Header(...),x_signature:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail ="Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        ind = False
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if chat["id"] == req.chat_id:
                chat["messages"].append({
                    "username":req.username,
                    "date":req.date if req.date != "" else datetime.now(),
                    "call_type":req.call_type,
                    "id":str(uuid.uuid4()),
                    "long":req.long
                }) 
                second_user = get_except(req.username)
                write_calls_history(req.username,second_user,req.call_type,str(datetime.now()))
                with open(chats_file,"w") as file:
                    json.dump(data,file)
                ind = True
        if not ind:
            raise HTTPException(status_code = 404,detail = "Chat not found")          
    except Exception as e:
        raise HTTPException(sttaus_code = 400,detail = f"Error : {e}")  
    
@app.post("/get/{username}/contacts",dependencies = [Depends(safe_get)])
async def get_user_contacts(username:str):
    if not  is_user_exists(username):
        raise HTTPException(status_code = 404,detail = "User doesnt exists")
    try:
        contacts = []
        with open(chats_file,"r") as file:
            data = json.load(file)
        for chat in data:
            if username in chat["users"]:
                second_user = get_except(username,chat["users"])
                contacts.append(second_user)
        return contacts       
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
@app.post("/get/{username}/recent",dependencies=[Depends(safe_get)])
async def get_user_recent(username:str):
    if not is_user_exists(username):
        raise HTTPException(status_code=404,detail = "User not found")
    try:
        with open(recent_file,"r") as file:
            data = json.load(file)
        for user in data:
            if user["username"] == username:
                return user["recent"]    
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}") 
#ADMIN 
class DeleteUser(BaseModel):
    username:str
    token:str
@app.post("/delete/user")
async def delete_user(req:DeleteUser,x_authorization = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,detail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        async def delete_user_psw(username:str):
            async with aiofiles.open(users_file,"r") as file:
                cont = await file.read()
                data = json.loads(cont)
            if username in data:
                del data[username]
            else:
                print(f"User : {username} not found")    
            async with aiofiles.open(users_file,"w") as file:
                await file.write(json.dumps(data,indent = 2))

        async def set_deleted_avatar(username:str):
            async with aiofiles.open(prof_file,"r") as file:
                cont = await file.read()
                data = json.loads(cont)
            if username in data:
                data[username] = "" #deafult avatar pictiure that deleted account 
                async with aiofiles.open(prof_file,"w") as file:
                    await file.write(json.dumps(data,indent= 2))
            else:
                print(f"User {username} not found")



        async def delete_recent_history(username:str):
            async with aiofiles.open(prof_file,"r") as file:
                cont = await file.read()
                data = json.loads(file)
                #DEBUG
                print(type(data))
            for user in data:
                if user["username"] == username:
                    ind = data.index(user)
                    data.pop(ind)
                    async with aiofiles.open(prof_file,"w") as file:
                        json.dump(data,file)
        async def log_out(token:str):
            payload = jwt.decode(req.token,get_secret(),algorithms=["HS256"])
            username = payload.get("sub")
            token_find = find_refresh_token(req.token)
            if token_find != -1:
                if token_find["username"] == username:
                    delete_refresh_token(req.token)
                else:
                    raise HTTPException(status_code = 403,detail = "Invalid token")    
            else:
                raise HTTPException(status_code = 404,detail  = "Token not found")  
        async def run(username:str,token:str):
            try:
                await asyncio.gather(
                delete_user_psw(username),
                set_deleted_avatar(username),
                delete_recent_history(username),
                log_out(token)
            )
            except Exception as e:
                raise HTTPException(status_code = 400,detail = f"Error : {e}")
        await run(req.username,req.token)


    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")
class DeleteFromCallHistory(BaseModel):   
    username:str
    call_id:str
@app.post("/delete/call/history")
async def delete_call_history(req:DeleteFromCallHistory,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,deatil = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 401,detail = "Invalid signature")
    try:
        f = False
        with open(history_calls,"r") as file:
            data = json.load(file)
        for user in data:
            if user["username"] == req.username:
                for call in user["calls"]:
                    if call["id"] == req.call_id:
                        ind =  user["calls"].index(call)
                        user["calls"].pop(ind)
                        f = True
                        with open(history_calls,"w") as file:
                            json.dump(data,file)
        if not f:
            raise HTTPException(status_code = 404,detail = "Call not found")                    
    except Exception as e:
        raise HTTPException(status_code = 400,deatil = f"Error : {e}")   
@app.get("/get/{username}/call_history",dependencies=[Depends(safe_get)])
async def get_user_history(username:str):
    try:
        with open(history_calls,"r") as file:
            data = json.load(file)
        for user in data:
            if user["username"] == username:
                return user["calls"]
        raise HTTPException(status_code = 404,detail = "Not found")
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")   
class ClearUserHistory(BaseModel):
    username:str
@app.post("/clear/user/history")
async def clear_history(req:ClearUserHistory,x_authorization:str = Header(...),x_signature:str = Header(...),x_timestamp:str = Header(...)):
    if not check_autorizations(x_authorization):
        raise HTTPException(status_code = 401,deatail = "Authorization error")
    if not verify_signature(req,x_signature,x_timestamp):
        raise HTTPException(status_code = 401,deatil = "Invalid signature")
    try:
        ind = False
        with open(history_calls,"r") as file:
            data = json.load(file)
        for user in data:
            if user["username"] == req.username:
                user["calls"] = []
                with open(history_calls,"w") as file:
                    json.dump(data,file)
                ind = True
        if not ind:
            raise HTTPException(status_code = 404,deatil = "User not found")            
    except Exception as e:
        raise HTTPException(status_code = 400,detail = f"Error : {e}")           
#---- RUN ----
def run_api():
    uvicorn.run(app,host = "0.0.0.0",port = 8080)
if __name__ == "__main__":
    run_api()
import requests
import hashlib
import asyncio
import uuid
import hmac
import json
import time
from jose import JWTError,jwt





def print_lux():
    lux_art = """
    ██╗      ██╗   ██╗██╗  ██╗
    ██║      ██║   ██║╚██╗██╔╝
    ██║      ██║   ██║ ╚███╔╝ 
    ██║      ██║   ██║ ██╔██╗ 
    ███████╗ ╚██████╔╝██╔╝ ██╗
    ╚══════╝  ╚═════╝ ╚═╝  ╚═╝
    """
    print("\033[1;35m" + lux_art + "\033[0m")
print_lux()
def print_login_register_menu():
    menu = """
    ╔══════════════════════════════════════════════════╗
    ║                      LUX                         ║
    ╠══════════════════════════════════════════════════╣
    ║                                                  ║
    ║          ████████████████████████████████        ║
    ║                                                  ║
    ║           ╔════════════════════════════╗         ║
    ║           ║       » 1. LOGIN  «        ║         ║
    ║           ║    ────────────────────    ║         ║
    ║           ║       » 2. REGISTER «      ║         ║
    ║           ╚════════════════════════════╝         ║
    ║                                                  ║
    ║          ████████████████████████████████        ║
    ║                                                  ║
    ║          [1] LOGIN    |    [2] REGISTER          ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
    """
    print("\033[1;36m" + menu + "\033[0m")
print_login_register_menu()
session = input("> ")

while session.lower() != "1" and session.lower() != "2":
    print("INVALID OPTION")
    session = input("> ")
  


secrets_file = "/Users/ivan/LUX-Call/data/secrets.json"
BASE_URL = "http://0.0.0.0:8080"


def hash_password(psw:str) -> str:
    bt = psw.encode("utf-8")
    hashed = hashlib.sha256(bt).hexdigest()
    return str(hashed)

def get_api_key() -> str:
    try:
        with open("secrets.json","r") as file:
            data = json.load(file)
        if not data.get("API"):
            raise KeyError("Key not found")
        else:
            return data["API"]

    except Exception as e:
        print(f"Error : {e}")
        raise TypeError("API key error")

def get_user_public_key(username:str) -> str:
    try:
        url = f"{BASE_URL}/get/user/public/key/{username}"
        headears = {
            "X-API-KEY":get_api_key()
        }
        resp = requests.get(url,headers= headears)
        return resp.json()
    except Exception as e:
        print(f"Key error : {e}")
        raise TypeError("Key Error")
def get_private_key() -> str:
    try:
        with open("keys.json","r") as file:
            data = json.load(file)
        if not data.get("key"):
            KeyError(" no such key")
        else:
            return data["key"]    
    except Exception as e:
        print(f"Error : {e}")
        TypeError("Error while private")    
def get_key() -> str:
    try:
        with open(secrets_file,"r") as file:
            data = json.load(file)
        return data["sign"]    
    except Exception as e:
        print(f"Exception : {e}")
class SigantureClient():
    def __init__(self,key:str):
        self.key = key
    def generate_siganture(self,data:dict) -> str:
        data_to_ver = data.copy()
        data_to_ver.pop("signature",None)
        data_str = json.dumps(data_to_ver, sort_keys=True, separators=(',', ':'))
        expected_signature = hmac.new(self.key.encode(), data_str.encode(), hashlib.sha256).hexdigest()
        return str(expected_signature)
    def verify_signature(self,data: dict, received_signature: str) -> bool:
        if time.time() - data.get('timestamp', 0) > 300:
            print("====== DEBUG =======")
            print("TIME SECURITY ERROR")
            return False
        
        
        data_to_verify = data.copy()
        data_to_verify.pop("signature", None)
        
        data_str = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':'))
        expected_signature = hmac.new(self.key.encode(), data_str.encode(), hashlib.sha256).hexdigest()
        
        return hmac.compare_digest(received_signature, expected_signature)
siganture_middleware = SigantureClient(get_key())
def register(username:str,psw:str) -> bool:
    url = f"{BASE_URL}/register"
    data = {
        "username":username,
        "psw":hash_password(psw)
    }
    headers = {
        "X-Signature": siganture_middleware.generate_siganture(data),
        "X-Timestamp": str(int(time.time())),
        "Content-Type": "application/json"
    }
    resp = requests.post(url,json = data,headers=headers)
    return resp.status_code == 200
def login(username:str,psw:str):
    try:
        url = f"{BASE_URL}/login"
        data = {
            "username":username,
            "psw":hash_password(psw)
        }
        headers = {
            "X-Signature":siganture_middleware.generate_siganture(data),
            "X-Timestamp":str(int(time.time()))
        }
        resp = requests.post(url,json = data,headers=headers)
        print(f"JSON : {resp.json}")
        print(f"TEXT : {resp.text}")
        return {
            "status_code":resp.status_code,
            "token":resp.json()["access_token"],
            "refresh":resp.json()["refresh_token"]
        }
    except Exception as e:
        print(f"Error : {e}")
        raise TypeError("Login Error")
user_data = {}    
if session.lower() == "1": 
    username = input("Username: ")
    password = input("Password: ")
    reg_ind = login(username,password)
    print(reg_ind)
    while not reg_ind["status_code"] == 200:
        print("WRONG DATA")
        username = input("Username: ")
        password = input("Password: ")
    print("LOGIN SUCCESSFULL")
    user_data["username"] = username
    user_data["jwt_token"] = reg_ind["token"]
    user_data["refresh"] = reg_ind["refresh"]

    

if session.lower() == "2":

    username = input("Username: ")
    password = input("Create a password: ")
    reg_ind = register(username,password)
    while not reg_ind:
        print("THIS USER ALREADY EXISTS")
        username = input("Username: ")
        password = input("Create a password: ")
    print("REGISTRATION SUCCESSFULL")
    user_data["username"] = username
def get_user_chats(username:str):
    try:
        pass
    except Exception as e:
        print(f"Error : {e}")
        raise TypeError("Error get user chats")

if user_data.get("username"):
    pass
    

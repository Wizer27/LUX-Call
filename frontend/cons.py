import requests
import hashlib
import asyncio
import uuid
import hmac
import json
import time

secrets_file = "/Users/ivan/LUX-Call/data/secrets.json"


def get_key() -> str:
    try:
        with open(secrets_file,"r") as file:
            data = json.load(file)
             
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
siganture_middleware = SigantureClient()
username = input("Username: ")
pasw = input("Password: ")
def register(username:str,psw:str) -> bool:
    url = "http://0.0.0.0:8080/register"
    data = {
        "username":username,
        "psw":psw
    }
    headers = {
        "signature":siganture_middleware.generate_siganture(data),
        "x_timestamp":str(time.time())
    }
    resp = requests.post(url,json = data,headers=headers)
    print(f"JSON : {resp.json}")
    print(f"TEXT : {resp.text}")
    print(F"CODE : {resp.status_code}")
    return resp.status_code == 200
register(username,pasw)


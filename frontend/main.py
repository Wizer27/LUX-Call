import streamlit as st
import json
import requests 
import hashlib
import hmac
import time



class GenerateSignature():
    def __init__(self,secret_key,api_key):
        self.secret_key = secret_key
        self.api_key = api_key
    def generate(self,data,timestamp):
        message = data + timestamp + self.secret_key
        
       
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature    


def hash_password(password:str) -> str:
    password_bytes = password.encode("utf-8")
    hashed = hashlib.sha256(password_bytes).hexdigest()
    return hashed 
def get_secret_key() -> str:
    with open("data/secrets.json","r") as file:
        data = json.load(file)
    try:
        return data["key"]
    except KeyError:
        return "Error"    

def get_api_key() -> str:
    with open("data/secrets.json","r") as file:
        data = json.load(file)
    try:
        return data["key"]
    except KeyError:
        return "Error"    
    

def register_new_user(username:str,hash_password:str) -> bool:
    try:
        url = "http://0.0.0.0:8080/api.register"
        data = {
            "username":username,
            "password":hash_password
        }
        main_siganature = GenerateSignature(get_secret_key(),get_api_key())
        json_data = json.dumps(data)
        timestamp = str(int(time.time()))
        signature = main_siganature.generate(json_data,timestamp)
        headers = {
            "Content-Type": "application/json",
            "X-Signature": signature,
            "X-Timestamp": timestamp,
            "X-API-Key": get_api_key()
        }
        try:
            resp = requests.post(url,json = data,headers=headers)
            #DEBUG
            print(resp.status_code)
            print(resp.text)
        except Exception as e:
            raise Exception 
    except Exception as e:
        return False
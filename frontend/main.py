import streamlit as st
import json
import requests 
import hashlib
import hmac
import time



if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'show_register' not in st.session_state:
    st.session_state.show_register = False 
if 'username' not in st.session_state:
    st.session_state.username = ""


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
    with open("/Users/ivan/LUX-Call/data/secrets.json","r") as file:
        data = json.load(file)
    try:
        return data["key"]
    except KeyError:
        return "Error"    

def get_api_key() -> str:
    with open("/Users/ivan/LUX-Call/data/secrets.json","r") as file:
        data = json.load(file)
    try:
        return data["key"]
    except KeyError:
        return "Error"    
    

def register_new_user(username:str,password:str) -> bool:
    try:
        url = "http://0.0.0.0:8080/api/register"
        data = {
            "username":username,
            "password":password
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
            return resp.status_code == 200
        except Exception as e:
            print(f"Exception1: {e}")
    except Exception as e:
        print(f"Exception2 : {e}")
        return False

def login(username:str,pasw:str) -> bool:
    url = "http://0.0.0.0:8080/api/login"
    data = {
        "username":username,
        "psw":pasw
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
        return resp.status_code == 200
    except Exception as e:
        print(f"Error : {e}")




if not st.session_state.logged_in:
    st.set_page_config(layout="wide")

    # CSS для фонового изображения
    st.markdown(
        """
        <style>
        .stApp {
            background-image: url("https://sdmntprnortheu.oaiusercontent.com/files/00000000-5354-61f4-8366-13d2ef546511/raw?se=2025-07-27T08%3A19%3A55Z&sp=r&sv=2024-08-04&sr=b&scid=fa3ec800-3e9b-5ebe-b0c0-a23e05dc2e5f&skoid=b928fb90-500a-412f-a661-1ece57a7c318&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2025-07-27T05%3A28%3A47Z&ske=2025-07-28T05%3A28%3A47Z&sks=b&skv=2024-08-04&sig=4%2BESOEXeHX1wnQ4h3JvcwnCGCrRgdYh7PsnkEZIc290%3D");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed;
        }
        </style>
        """,
        unsafe_allow_html=True
    )    
    
    if st.session_state.show_register:
        st.title("📝 Registration")
        new_username = st.text_input("Username", key="reg_user")
        new_password = st.text_input("Password", type="password", key="reg_pass1")
        confirm_password = st.text_input("Retype the password", type="password", key="reg_pass2")
        
        if st.button("Create an account"):
            if not new_username or not new_password:
                st.error("Fill all the field.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")       
            else:    
                api_answer = register_new_user(new_username, hash_password(new_password)) 
                if not api_answer:
                    st.error("This username is already taken.")
                else:    
                    st.success("Successfully created an account. Now you can sign in.")
                    st.session_state.show_register = False
                            
        if st.button("← Back to sign in"):
            st.session_state.show_register = False
            st.rerun()
    
    else:
        st.title("🔒 Sign in ")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Sign in"):
            if login(username, hash_password(password)):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Wrong password or username")
                
        if st.button("Sign up"):
            st.session_state.show_register = True
            st.rerun()
    
    st.stop()
st.success("Loged IN")



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
    with open("/Users/ivan/LUX-Call/data/secrets.json","r") as file:
        data = json.load(file)
    try:
        return data["key"]
    except KeyError:
        return "Error"    

def get_api_key() -> str:
    with open("/Users/ivan/LUX-Call/data/secrets.json","r") as file:
        data = json.load(file)
    try:
        return data["key"]
    except KeyError:
        return "Error"    
    

def register_new_user(username:str,password:str) -> bool:
    try:
        url = "http://0.0.0.0:8080/api/register"
        data = {
            "username":username,
            "password":hash_password(password)
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
            return resp.status_code == 200
        except Exception as e:
            print(f"Exception1: {e}")
    except Exception as e:
        print(f"Exception2 : {e}")
        return False

async def create_new_chat(username1:str,username2:str):
    url = "http://0.0.0.0:8080/api/create_new_chat"
    data = {
        "user1":username1,
        "user2":username2
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
    except Exception as e:
        raise Exception

import requests
import hashlib
import asyncio
import uuid
import hmac
import json
import time


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
    
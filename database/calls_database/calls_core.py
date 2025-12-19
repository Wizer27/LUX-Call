from calls_models import metadata_obj,calls_table
from calls_sqli import sync_engine
from sqlalchemy import select,update,delete,or_
from typing import List
from datetime import datetime
import uuid

def create_table():
    metadata_obj.create_all(sync_engine)
def get_all_data():
    with sync_engine.connect() as conn:
        try:
            stmt  = select(calls_table)
            res = conn.execute(stmt)
            return res.fetchall()
        except Exception as e:
            return Exception(f"Error : {e}")
def write_new_call(username:str,to_user:str,call_type:str,time:int):
    with sync_engine.connect() as conn:
        try:
            stmt = calls_table.insert().values(
                id = str(uuid.uuid4()),
                username = username,
                called_to = to_user,
                date = str(datetime.now()).split()[0],
                call_type = call_type,
                time = time
            )
            conn.execute(stmt)
            conn.commit()
        except Exception as e:
            return Exception(f"Call error {e}")     
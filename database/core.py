from sqlalchemy import text,select,or_
from models import user_data_table,metadata_obj
from sql_i import sync_engine
from typing import List


def create_table():
    metadata_obj.drop_all(sync_engine)
    metadata_obj.create_all(sync_engine)

def is_user_exists(username:str) -> bool:
    with sync_engine.connect() as conn:
        try:
            stmt = select(user_data_table.c.username).where(user_data_table.c.username == username)
            res = conn.execute(stmt)
            data = res.fetchall()
            if data is not None:
                return len(data) != 0
            return False
        except Exception as e:
            return Exception(f"Error : {e}")
def register(username:str,hash_psw:str) -> bool:
    with sync_engine.connect() as conn:
        if is_user_exists(username):
            return False
        try:
            stmt = user_data_table.insert().values(
                username = username,
                hash_psw = hash_psw
            )
            conn.execute(stmt)
            conn.commit()
            return True
        except Exception as e:
            return Exception(f"Error : {e}")
def get_all_data():
    with sync_engine.connect() as conn:
        try:
            stmt = select(user_data_table.c)
            res = conn.execute(stmt)
            return res.fetchall()
        except Exception as e:
            return Exception(f"Error : {e}")   
def login(username:str,hash_psw:str) -> bool:
    if not is_user_exists(username):
        return False
    with sync_engine.connect() as conn:
        try:
            stmt = select(user_data_table.c.hash_psw).where(user_data_table.c.username == username)
            res = conn.execute(stmt)
            data = res.fetchone()
            if data is not None:
                return data[0] == hash_psw
        except Exception as e:
            return Exception(f"Error : {e}")

def get_user_avatar(username:str):
    if not is_user_exists(username):
        return False 
    with sync_engine.connect() as conn:
        try:
            stmt = select(user_data_table.c.avatar).where(user_data_table.c.username == username)
            res = conn.execute(stmt)
            data = res.fetchone()
            return data[0]
        except Exception as e:
            return Exception(f"Error : {e}")
def write_user_avatar(username:str,avatar_64:str) -> bool:
    if not is_user_exists(username):
        return False
    with sync_engine.connect() as conn:
        try:
            stmt = user_data_table.update().where(user_data_table.c.username).values(avatar = avatar_64)
            conn.execute(stmt)
            conn.commmit()
        except Exception as e:
            return Exception(f"Error : {e}")
def search_users(search:str) -> List[str]:
    with sync_engine.connect() as conn:
        try:
            stmt = select(user_data_table.c.username).where(or_(
                user_data_table.c.username == search.lower(),
                user_data_table.c.username.ilike(f"%{search}%")
                ))
            res = conn.excute(stmt)
            return res.fetchall()
        except Exception as e:
            return Exception(f"Error : {e}")  
                  
             

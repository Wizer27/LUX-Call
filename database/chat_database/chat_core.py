from sqlalchemy import text,select,or_,any_
from chat_models import chat_data_table,metadata_obj
from chat_sqli import sync_engine
import uuid
from typing import List,Optional



def create_table():
    #metadata_obj.drop_all(sync_engine)
    metadata_obj.create_all(sync_engine)


def create_emty_chat():
    with sync_engine.connect() as conn:
        try:
            stmt = chat_data_table.insert().values(
                id = str(uuid.uuid4()),
                messages = [],
                users = []
            )
            conn.execute(stmt)
            conn.commit()
        except Exception as e:
            return Exception(f"Error : {e}")
def create_chat(user1:str,user2:str):
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table.c.id).where(chat_data_table.c.users == [])
            res = conn.execute(stmt)
            data = res.fetchone()
            if data is not None:
                id_ = data[0]
                update_stmt = chat_data_table.update().where(chat_data_table.c.id == id_).values(
                    players = [user1,user2]
                )
                conn.execute(update_stmt)
                conn.commit()
                return id_
            else:
                return "Chat not found"
        except Exception as e:
            return Exception(f"Error : {e}")
def clear_the_chat(id_:str):
    with sync_engine.connect() as conn:
        try:
            stmt = chat_data_table.update().where(chat_data_table.c.id == id_).values(messages = [])
            conn.execute(stmt)
            conn.commit()
        except Exception as e:
            return Exception(f"Error : {e}")  
def delete_the_chat(id_:str):
    with sync_engine.connect() as conn:
        try:
            stmt = chat_data_table.update().where(chat_data_table.c.id == id_).values(
                users = [],
                messages = []
            )
            conn.execute(stmt)
            conn.commit()
        except Exception as e:
            return Exception(f"Error : {e}")  
def send_messages(chat_id:str,username:str,message:str,files:Optional[List[str]]):
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table.c.messages).where(chat_data_table.c.id == chat_id)
            res = conn.execute(stmt)
            data = res.fetchone()
            if data is not None:
                new_messages = data[0]
                new_messages.append({
                    "username":username,
                    "id":str(uuid.uuid4()),
                    "message":message,
                    "files":files
                })
                update_stmt = chat_data_table.update().where(chat_data_table.c.id == chat_id).values(messages = new_messages)
                conn.execute(update_stmt)
                conn.commit()
        except Exception as e:
            return Exception(f"Error : {e}")  
def delete_the_message(chat_id:str,message_id:str):
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table.c.messages).where(chat_data_table.c.id == chat_id)
            res = conn.execute(stmt)
            data = res.fetchone()
            if data is not None:
                messages = data[0]
                for message in messages:
                    if message["id"] == message_id:
                        ind = messages.index(message)
                        messages.pop(ind)
                        update_stmt = chat_data_table.c.update().where(chat_data_table.c.id ==  chat_id).values(
                            messages = messages
                        )
                        conn.execute(update_stmt)
                        conn.commit()
        except Exception as e:
            return Exception(f"Error : {e}") 
def get_chat_messages(chat_id:str):
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table.c.messages).where(chat_data_table.c.id == chat_id)
            res = conn.execute(stmt)
            data = res.fetchone()
            if data is not None:
                return data[0]
        except Exception as e:
            return Exception(f"Error : {e}")  
def user_have_chat(username1:str,username2:str):
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table.c.id).where(or_(
                chat_data_table.c.users == [username1,username2],
                chat_data_table.c.users == [username2,username1]
            ))
            res = conn.execute(stmt)
            data = res.fetchall()
            if data is not None:
                return len(data[0]) > 0
        except Exception as e:
            return Exception(f"Error : {e}")   
def leave_chat(chat_id:str,username:str):
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table.c.users).where(chat_data_table.c.id == chat_id)
            res = conn.execute(stmt)
            data = res.fetchone()
            if data is not None:
                chats_ = data[0]
                ind = chats_.index(username)
                chats_.pop(ind)
                update_stmt = chat_data_table.update().where(chat_data_table.id == chat_id).values(
                    users = chats_
                )
                conn.execute(update_stmt)
                conn.commit()
        except Exception as e:
            return Exception(f"Error : {e}")   
def get_user_chats(username:str) -> List:
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table).where(username == any_(chat_data_table.c.users))
            res = conn.execute(stmt)
            return res.fetchall()
        except Exception as e:
            return Exception(f"Error : {e}")                               
def get_all_data():
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table)
            res = conn.execute(stmt)
            return res.fetchall()
        except Exception as e:
            return Exception(f"Error : {e}")
print(send_messages("dd8e4d94-769a-4924-a1ad-c5c038e724bb","user1","test",[]))        
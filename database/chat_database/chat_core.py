from sqlalchemy import text,select
from chat_models import chat_data_table,metadata_obj
from chat_sqli import sync_engine
import uuid



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
def get_all_data():
    with sync_engine.connect() as conn:
        try:
            stmt = select(chat_data_table)
            res = conn.execute(stmt)
            return res.fetchall()
        except Exception as e:
            return Exception(f"Error : {e}")

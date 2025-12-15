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
            data = res.fetchall()
            print(data)
            
        except Exception as e:
            return Exception(f"Error : {e}")



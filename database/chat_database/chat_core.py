from sqlalchemy import text,select
from chat_models import user_data_table,metadata_obj
from chat_sqli import sync_engine



def create_table():
    #metadata_obj.drop_all(sync_engine)
    metadata_obj.create_all(sync_engine)


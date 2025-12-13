from sqlalchemy import text,select
from models import user_data_table,metadata_obj
from sql_i import sync_engine


def create_table():
    metadata_obj.create_all(sync_engine)


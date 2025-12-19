from calls_models import metadata_obj,calls_table
from calls_sqli import sync_engine
from sqlalchemy import select,update,delete,or_
from typing import List

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
print(get_all_data())        
from sqlalchemy import text,String,Column,Boolean,MetaData,ARRAY,Table
from sqlalchemy.dialects.postgresql import JSONB


metadata_obj = MetaData()

user_data_table = Table(
    "lux_call_user_data",
    metadata_obj,
    Column("username",String,primary_key=True),
    Column("hash_psw",String),
    Column("avatar",String)
)
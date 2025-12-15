from sqlalchemy import text,String,Column,Boolean,MetaData,ARRAY,Table
from sqlalchemy.dialects.postgresql import JSONB


metadata_obj = MetaData()

user_data_table = Table(
    "chat_data",
    metadata_obj,
    Column("id",String,primary_key=True),
    Column("messages",ARRAY(String)),
    Column("users",ARRAY(String))

)
from sqlalchemy import text,String,Column,Boolean,MetaData,ARRAY,Table
from sqlalchemy.dialects.postgresql import JSONB


metadata_obj = MetaData()

user_data_table = Table(
    "calls_data",
    metadata_obj,
    Column("id",String,primary_key=True),
    Column("called_to",String),
    Column("date",String),
    Column("call_type",String)

)
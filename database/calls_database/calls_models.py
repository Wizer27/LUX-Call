from sqlalchemy import text,String,Column,Boolean,MetaData,ARRAY,Table,Integer
from sqlalchemy.dialects.postgresql import JSONB


metadata_obj = MetaData()

calls_table = Table(
    "calls_data",
    metadata_obj,
    Column("id",String,primary_key=True),
    Column("username",String),
    Column("called_to",String),
    Column("date",String),
    Column("call_type",String),
    Column("time",Integer)
)
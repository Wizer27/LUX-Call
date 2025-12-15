from sqlalchemy import URL,text,create_engine
from chat_config import connect
from chat_models import metadata_obj,user_data_table




sync_engine =  create_engine(
    url = connect(),
    echo = False,
    pool_size = 5,
    max_overflow=10,
)
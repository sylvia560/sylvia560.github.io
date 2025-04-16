from pydantic import BaseModel
from typing import Optional

class Blog(BaseModel):
    title: str
    body: str
    publisded_at:Optional[bool]
    
    

       
class User(BaseModel):
    name:str
    email:str
    password:str
    
    
class ShowUser(BaseModel):
    name:str
    email:str
    class Config():
       orm_mode=True
       
        
class ShowBlog(Blog):
    title: str
    body: str
    creator: ShowUser
    class Config():
       orm_mode=True
        

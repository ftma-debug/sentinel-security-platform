from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from app import database
database.init_db()
app=FastAPI()
pwd_context=CryptContext(schemes=["argon2"], deprecated="auto")
def hashpwd(password):
    return pwd_context.hash(password)
#defining the routes
#get / (home)
@app.get("/")
def home():
    return{"message":"Welcome to my API !"}
#get /users
@app.get("/users")
def get_users():
    con=database.get_db_connection()
    cur=con.cursor()
    users=cur.execute("""SELECT id,username,email,role FROM users;
""").fetchall()
    con.close()
    return {"users":[dict(user)for user in users]}

#get /users/{user_id}(dynamic route)
@app.get("/users/{user_id}")
def get_user_with_id(user_id):
    con=database.get_db_connection()
    cur=con.cursor()
    user=cur.execute("""SELECT username,email,role FROM users WHERE id=?
""",
(user_id,)).fetchone()
    con.close()
    if user is None:
        raise HTTPException(status_code=404,detail="user not found")
    return dict(user)
#validtion using pydantic
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
#post /users (create new user)
@app.post("/users")
def create_user(user:UserCreate):
    con=database.get_db_connection()
    cur=con.cursor()
    cur.execute("""
INSERT INTO users 
(username,email,password_hash)
VALUES(?,?,?)
""",
(user.username,user.email,hashpwd(user.password))
)
    con.commit()
    user_id=cur.lastrowid
    con.close()
    return{"message":"user created successfully!",
           "user": {
               "id":user_id,
               "username":user.username,
               "email":user.email,
               "role":"user"
           }}
#delete /users/{user_id}
@app.delete("/users/{user_id}")
def delete_user(user_id):
    con=database.get_db_connection()
    cur=con.cursor()
    cur.execute("""DELETE FROM users WHERE id=?;
""",
(user_id,))
    if cur.rowcount==0:
        con.close()
        raise HTTPException(status_code=404,detail="user not found")
    con.commit()
    con.close()
    return {"message":f"User with id {user_id} deleted succcessfully !"}
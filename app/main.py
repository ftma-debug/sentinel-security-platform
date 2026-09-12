from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Response,Request
from fastapi import Depends
from pydantic import BaseModel
import secrets
import sqlite3
import requests 
from passlib.context import CryptContext
from datetime import datetime,timedelta
from app import database
database.init_db()
app=FastAPI()


#login
class UserLogin(BaseModel):
    username: str
    password: str




#record security events
def log_security_event(event_type,user_id=None,ip_address=None):
    con=database.get_db_connection()
    cur=con.cursor()
    cur.execute("""
    INSERT INTO security_events
    (event_type,user_id,ip_address)
    VALUES(?,?,?)
    """,(event_type,user_id,ip_address))
    con.commit()
    con.close()






def create_alert(alert_type,severity,user_id=None,ip_address=None,description=""):
    con=database.get_db_connection()
    cur=con.cursor()
    cur.execute("""INSERT INTO alerts 
    (alert_type,severity,user_id,ip_address,description)
    VALUES(?,?,?,?,?)""",(alert_type,severity,user_id,ip_address,description))
    con.commit()
    con.close()







def get_ip_address(request:Request):
    if request.client:
        return request.client.host
    return None








#auth 
@app.post("/auth/login")
def login(user:UserLogin ,response:Response,request:Request):
    con=database.get_db_connection()
    cur=con.cursor()
    result=cur.execute("""SELECT id,password_hash FROM users WHERE username=?
""",
(user.username,)).fetchone()
    attempts = cur.execute("""
    SELECT failed_attempts, blocked_until
    FROM login_attempts
    WHERE username=?
    """, (user.username,)).fetchone()

    if attempts is not None and attempts["blocked_until"] is not None:
        blocked_until = datetime.fromisoformat(attempts["blocked_until"])

        if datetime.utcnow() < blocked_until:
            con.close()
            log_security_event("LOGIN_BLOCKED",None,get_ip_address(request))
            raise HTTPException(
                status_code=403,
                detail="Too many failed attempts. Try again later."
            )
    if result is None:
        record_failed_attempts(user.username,cur)
        con.commit()
        con.close()
        log_security_event("LOGIN_FAILURE",None,get_ip_address(request))
        raise HTTPException(status_code=401,detail="Invalid user name or password")
    if verify_password(user.password,result["password_hash"]):
        
        session_id=secrets.token_urlsafe(32)
        created_at=datetime.utcnow()
        expires_at=created_at+timedelta(hours=1)
        exixting_sessions=cur.execute("""
        SELECT session_id FROM sessions WHERE user_id=? And expires_at >?
        """,(result["id"],datetime.utcnow())).fetchall()
        cur.execute("""
        INSERT INTO sessions
        (session_id,user_id,created_at,expires_at)
        VALUES(?,?,?,?)
        """,(session_id,result["id"],created_at,expires_at))
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=3600 # max age of cookie is 3600s so 1h
        )
        cur.execute("""UPDATE login_attempts 
        SET failed_attempts=0,blocked_until=NULL
        WHERE username=?""",(user.username,))
        con.commit()
        log_security_event("LOGIN_SUCCESS",result["id"],get_ip_address(request))
        if not exixting_sessions :
            log_security_event("SESSION_CREATED",result["id"],get_ip_address(request))
        else:
            log_security_event("SESSION_ROTATED",result["id"],get_ip_address(request))
            for session in exixting_sessions :
                cur.execute("""DELETE FROM sessions WHERE session_id=?""",(session["session_id"],))
        con.commit()
        con.close()
        
        return {"message":"login successfully !"}
    else:
        record_failed_attempts(user.username,cur)
        con.commit()
        con.close()
        log_security_event("LOGIN_FAILURE",result["id"],get_ip_address(request))
        raise HTTPException(status_code=401,detail="Invalid username or password")



#record failed attempts
def record_failed_attempts(username,cur):
    attempt=cur.execute("""SELECT failed_attempts,blocked_until FROM login_attempts WHERE username=? ;""",(username,)).fetchone()
    if attempt is None:
        cur.execute("""INSERT INTO login_attempts 
                    (username,failed_attempts)
                    VALUES(?,?)""",(username,1))
        return
    failed_attempts=attempt["failed_attempts"]+1
    if failed_attempts>=5:
        blocked_until=datetime.utcnow()+timedelta(minutes=5)
        cur.execute("""UPDATE login_attempts 
                        SET blocked_until=?, failed_attempts=? WHERE username=?""",(blocked_until,failed_attempts,username))
    else:
        cur.execute("""
            UPDATE login_attempts
            SET failed_attempts=?
            WHERE username=?
        """, (failed_attempts, username))






    
def get_current_user(request:Request):
    session_id=request.cookies.get("session_id")
    if session_id is None:
        log_security_event("UNAUTHORIZED_ACCESS",ip_address=get_ip_address(request))
        raise HTTPException(status_code=401,detail="Not Authantificated")
    con=database.get_db_connection()
    cur=con.cursor()
    result=cur.execute("""SELECT user_id,expires_at FROM sessions WHERE session_id=?
    """,(session_id,)).fetchone()
    if result is None:
        con.close()
        log_security_event("INVALID_SESSION",ip_address=get_ip_address(request))
        raise HTTPException(status_code=401,detail="invalid session")
    expires_at=datetime.fromisoformat(result["expires_at"])#Extracts the expiry time from the session data and converts it from a string (ISO format) back into a Python datetime object so you can compare it with the current time.
    if datetime.utcnow()>expires_at:
        log_security_event("SESSION_EXPIRED",result["user_id"],get_ip_address(request))
        con.close()
        raise HTTPException(status_code=401,detail="session expired")
    user=cur.execute("""SELECT id,username,email,role FROM users WHERE id=?""",
                     (result["user_id"],)).fetchone()
    if user is None:
        con.close()
        raise HTTPException(status_code=401,detail="user not found")
    con.close()
    return dict(user)


def require_admin(request:Request,current_user:dict=Depends(get_current_user)):
    if current_user["role"] !='admin':
        log_security_event("FORBIDDEN_ACCESS",current_user["id"],get_ip_address(request))
        raise HTTPException(status_code=403,detail="admin access required")
    return current_user



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
def get_users(current_user:dict=Depends(require_admin)):
    con=database.get_db_connection()
    cur=con.cursor()
    users=cur.execute("""SELECT id,username,email,role FROM users;
""").fetchall()
    con.close()
    return {"current_user":current_user,
            "users":[dict(user)for user in users]}

#get /users/{user_id}(dynamic route)
@app.get("/users/{user_id}")
def get_user_with_id(request:Request,user_id: int,current_user:dict=Depends(get_current_user)):
    if current_user["role"] !="admin" and current_user["id"]!=user_id:
        log_security_event(
        "FORBIDDEN_ACCESS",
        current_user["id"],
        get_ip_address(request)
)
        raise HTTPException(status_code=403,detail="You are not allowed to access this user")
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
def create_user(request:Request,user:UserCreate,current_user:dict=Depends(require_admin)):
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
    log_security_event("USER_CREATED",user_id,get_ip_address(request))
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
def delete_user(request:Request,user_id: int,current_user:dict=Depends(require_admin)):
    con=database.get_db_connection()
    cur=con.cursor()
    cur.execute("""DELETE FROM users WHERE id=?;
""",
(user_id,))
    if cur.rowcount==0:
        con.close()
        raise HTTPException(status_code=404,detail="user not found")
    log_security_event("USER_DELETED",user_id,get_ip_address(request))
    con.commit()
    con.close()
    return {"message":f"User with id {user_id} deleted succcessfully !"}

#verify password
def verify_password(password,password_hashed):
    return pwd_context.verify(password,password_hashed)





#logout
@app.post("/auth/logout")
def logout(request:Request,response:Response):
    session_id=request.cookies.get("session_id")
    response.delete_cookie("session_id")
    if session_id is None:
        raise HTTPException(status_code=401 ,detail="Not authenticated")
    con=database.get_db_connection()
    cur=con.cursor()
    user_id=cur.execute("SELECT user_id FROM sessions WHERE session_id=? ",(session_id,)).fetchone()
    cur.execute("""DELETE FROM sessions WHERE session_id=?""",
                (session_id,))
    con.commit()
    if user_id is not None:
        log_security_event("LOGOUT",user_id[0],get_ip_address(request))
    con.close()
    return{"message":"logged out successfully!"}










#get security events 
@app.get("/security/events")
def get_security_events(event_type:str|None = None ,user_id:int|None =None,ip_address:str|None=None,limit:int |None=None,offset:int|None=None,current_user:dict=Depends(require_admin)):
    con=database.get_db_connection()
    cur=con.cursor()
    query="""SELECT id,event_type,user_id,ip_address,timestamp FROM security_events WHERE 1=1"""
    params=[]
    if event_type is not None:
        query+=""" AND event_type=?"""
        params.append(event_type)
    if user_id is not None:
        query+=""" AND user_id=?"""
        params.append(user_id)
    if ip_address is not None:
        query+=""" AND ip_address=?"""
        params.append(ip_address)
    query+=""" ORDER BY timestamp DESC"""
    if limit is not None:
        query+=""" LIMIT ?"""
        params.append(limit)
    if offset is not None:
        query+=""" OFFSET ?"""
        params.append(offset)
    security_events=cur.execute(query,params).fetchall()
    con.close()
    if len(security_events)==0:
        return{"current_user":current_user,
               "security events":[]}
    else:
        return{"current_user":current_user,
                "security events":[dict(event)for event in security_events]}
    


    

    
                










#test
hashed=hashpwd("tahyaljazayer")
print(hashed)
print(verify_password("tahyaljazayer",hashed))
print(verify_password("123",hashed))













const loginform=document.getElementById("login-form");
const errormsg=document.getElementById("error-message");
loginform.addEventListener("submit",async(event)=>{
    const username=document.getElementById("username");
    const password=document.getElementById("password");
    try{
        const response =await fetch("http://127.0.0.1:8000/auth/login",{
            method:"post",
            headers:{
                "content-type":"application/json"
            },
            credentials:"include",
            body:JSON.stringify({
                username:username,
                password:password
            })
        });
        const data =await response.json();
        if(!response.ok){
            errormsg.textContent=data.detail;
            return;
        }
        window.location.href="dashboard.html"
    }catch(error){
        errormsg.textContent="Unable to connect to the server.";
        console.error(error);
    }
})

import requests 

url="http://www.introbao.com:8000/login.html" 
post={"user":"admin", "passwd":"introbao", "groupid":"1"} 
x=requests.post(url, data=post).text
print x
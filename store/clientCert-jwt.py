
import json
import requests
import html

clientCrt = "./clientBob.crt"
clientKey = "./clientBob.key"
url = "https://localhost:8443/auth"
payload = { "someId": "myID" }
certServer = './rootCA.crt'
headers = {'Connection': 'keep-alive',
'Upgrade-Insecure-Requests': 1,
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'Sec-Fetch-Site': 'none',
'Sec-Fetch-Mode': 'navigate',
'Sec-Fetch-User': '?1',
'Sec-Fetch-Dest': 'document',
'Accept-Encoding': 'gzip, deflate, br',
'Accept-Language': 'en-US,en;q=0.9'
}
#r = requests.post(url, data=json.dumps(payload), verify=certServer,  headers=headers, cert=(clientCrt, clientKey))
r = requests.get(url, verify=certServer,  cert=(clientCrt, clientKey))
print(r.status_code)
respData = r.text

ind1 = respData.find("{&quot;result&quot")
print("ind " + str(ind1))
ind2 = respData.find("}}")
print("ind2 " + str(ind2))

respData = respData[ind1:ind2]
respData = respData + "}}"

respData = html.unescape(respData)
# print(respData)
print("\r\n result=")
j = json.loads(respData)

jwt = j["result"]["jwt"]
print("jwt=")
print(jwt)
url = "http://192.168.254.97:8050/api/time"
#url = "http://localhost:8080/api/time"
r = requests.get(url, headers={'Authorization': 'bearer ' + jwt })
respData = r.text

print("resp from " + url)
print(respData)

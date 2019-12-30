This is part III of a series of articles on **Spring security** topic. In this part, we will use *X.509* certificate authentication

Curl commands:
```
curl --insecure https://localhost:8443
curl --insecure https://localhost:8443/admin
curl --insecure --cert-type P12 --cert client_marone.p12:client1 https://localhost:8443/admin
curl --insecure --cert-type P12 --cert client_marone.p12:client1 https://localhost:8443/protected
```

More articles can be found here: https://wstutorial.com


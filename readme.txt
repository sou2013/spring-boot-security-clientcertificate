??? **************************  keystore password is null  ************  
make sure your client cert is not expired

 2014  begin
 //create CA private key and crt. pswd=changeit, append this for easy -subj '/C=US/ST=California/CN=emoclient/EMAILADDRESS=myexpressoemail@mymailhost.com'
 2015  openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
 openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout fakeCA.key -out fakeCA.crt -subj '/C=US/ST=California/CN=fakeCN/EMAILADDRESS=myexpressoemail@mymailhost.com'
 
 // create server's priv key and cert request
 2007  openssl req -new -newkey rsa:4096 -keyout localhost.key -out localhost.csr
 
 //sign the request with our rootCA.crt certificate and its private key
 2008  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext
 
 // view crt
 2011  openssl x509 -in localhost.crt -text
 
 // combine server crt and priv key into a .p12 file.   
 openssl pkcs12 -export -out localhost.p12 -name "localhost" -inkey localhost.key -in localhost.crt
 
 
 // create client cert req for testuser
 openssl req -new -newkey rsa:4096 -nodes -keyout clientTestuser.key -out clientTestuser.csr -subj '/CN=testuser'

// sign testuser requ with CA crt
 openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientTestuser.csr -out clientTestuser.crt -days 3650 -CAcreateserial
 
 openssl pkcs12 -export -out clientTestuser.p12 -name "testuser" -inkey clientTestuser.key -in clientTestuser.crt
 
 2018  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial
 2019  rm -rf clientBob.*
 2020  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial


 2002  keytool -importkeystore -srckeystore localhost.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS
 2003  ll
 2004  keytool -importkeystore -srckeystore localhost.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS
 2005  ll
 2006  openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
 
 2009  ll
 2010  ls -lat
 
 2012  openssl pkcs12 -export -out localhost.p12 -name "localhost" -inkey localhost.key -in localhost.crt
 2013  ll
 2014  keytool -importkeystore -srckeystore localhost.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS


### leave all default, only set common name = Bob , next step
 2021  openssl req -new -newkey rsa:4096 -nodes -keyout clientBob.key -out clientBob.csr
 2022  ll
 2023  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial
 2024  openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
 2025  ll
 2026  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial
 2027  ll
 2028  openssl pkcs12 -export -out clientBob.p12 -name "clientBob" -inkey clientBob.key -in clientBob.crt
 2029  ll
 2030  openssl req -new -newkey rsa:4096 -nodes -keyout clientBob.key -out clientBob.csr
 2031  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial
 2032  ll
 2033  openssl pkcs12 -export -out clientBob.p12 -name "clientBob" -inkey clientBob.key -in clientBob.crt
 2034  cd ..
 2035  ll
 2036  cd spring-security-web-x509-client-auth/
 2037  mvn spring-boot:run
 2038  cd ..
 2039  cd store
 2040  keytool -import -trustcacerts -noprompt -alias ca -ext san=dns:localhost,ip:127.0.0.1 -file rootCA.crt -keystore truststore.jk
 2041  openssl req -new -newkey rsa:4096 -nodes -keyout clientBob.key -out clientBob.csr
 2042  openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial
 2043  ll
 2044  openssl pkcs12 -export -out clientBob.p12 -name "clientBob" -inkey clientBob.key -in clientBob.crt
 2045  ll
 2046  mv truststore.jk truststore.jks

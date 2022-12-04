Name : Murali Mohan Bugata
Email : mmohanb1@binghamton.edu
Tested on remote.cs : yes

There are 2 java files JavaSSLClient.java and JavaSSLServer.java along with the certificate in mykeystore folder named trusted.examplekeystore. You would need to run below commands at the same location where these java code files reside.

1. make(run the make command to generate .class files for client and server)

Please run the command below to start the server(here 7020 is the parameter for server port and cert password being password). Please change the location of mykeystore folder appropriately per you location to point to the keystore ie, the value of "-Djavax.net.ssl.keyStore" before running -


2. jar cfe server.jar JavaSSLServer JavaSSLServer.class
3. java -jar -Djavax.net.ssl.keyStore=/home/mmohanb1/ICS/Project1/mykeystore/trusted.examplekeystore -Djavax.net.ssl.keyStorePassword=password "server.jar" 7020

Please run below command to start the client(arguments are remote.cs server domain/ip and port which is same as server port and password being password).
Please change the location of mykeystore folder appropriately per you location to point to the keystore ie, the value of "-Djavax.net.ssl.trustStore" before running-

4. jar cfe client.jar JavaSSLClient JavaSSLClient.class
5. java -jar -Djavax.net.ssl.trustStore=/home/mmohanb1/ICS/Project1/mykeystore/trusted.examplekeystore -Djavax.net.ssl.trustStorePassword=password "client.jar" remote03.cs.binghamton.edu 7020

Make sure you start the server first before starting the client.
Once the server and client are up and running, you can run ls, pwd and exit commands at client when it asks to enter something on the console.
#### JWT Generator
A flexible way to generate a JWT for any given application (using Public & private keys) 

##### Dependencies
* Java 11

##### Build
```bash
mvn clean package
```

#### Generating a public and private key
* Create a RSA Keypair 
```bash
openssl genrsa -out private.pem 2048
```
* Export the file into PKCS8 format (Java compatible)
```bash
openssl pkcs8 -topk8 -inform PEM -in private.pem -out private_key.pem -nocrypt
```
* Export public key for the private key
```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

**Note:** 
* Please stove away the private and public and private keys in a safe secured place. 
  Typically this is placed in /etc/security/<application> directory which will have restricted access
* Private key is required to generate the token. To verify the token only public key is enough.
   
##### Usage
```
usage: java -jar jwt-token-gen-0.1-shaded.jar
 -a,--audience <arg>      Audience
 -c,--claims <arg>        Custom claims Ex: claim:claimvalue
 -e,--expiry <arg>        Expiry in seconds
 -i,--issuer <arg>        Issuer
 -m,--algo <arg>          Algorithm
 -n,--noExpiry            No Expiry
 -p,--public <arg>        Path to public key (in pem format)
 -r,--permissions <arg>   Comma separated list of permissions
 -s,--private <arg>       Path to private key (in pem format)
 -u,--subject <arg>       Subject  
```

##### Examples
* Using short options (Token without expiry)
```bash
java -jar jwt-token-gen-0.1-shaded.jar -a "user" -i "testapp" -m "RS256" -p "public.pem" -s "private_key.pem" -u "mytestuser" -n \
    -c "test:test,test1:test1" -r "permission1,permission2" 
```
* Using long options (Token without expiry)
```bash
java -jar jwt-token-gen-0.1-shaded.jar --audience "user" --issuer "testapp" --algo "RS256" --public "public.pem" \ 
    --private "private_key.pem" --subject "mytestuser" --noExpiry --claims "test:test,test1:test1" \
    --permissions "permission1,permission2" 
```
* Token with expiry (of 30 days)
```bash
java -jar jwt-token-gen-0.1-shaded.jar --audience "user" --issuer "testapp" --algo "RS256" --public "public.pem" \ 
    --private "private_key.pem" --subject "mytestuser" --expiry "2592000" --claims "test:test,test1:test1" \
    --permissions "permission1,permission2" 
```

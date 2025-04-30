#### JWT Generator
A flexible way to generate a JWT for any given application (using Public & private keys) 

##### Dependencies
* Java 21

##### Build
```bash
mvn -U -Pnative -Dagent clean package
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
* Please store the private and public and private keys in a safe secured place. 
  Typically,
  this is placed in /etc/security/<application> directory which will have restricted access
* Private key is required to generate the token. To verify the token only public key is enough.
   
##### Usage
```bash
./token-generator -h
Usage: token-generator [-hnV] [-a=<audience>] [-c=<claims>] [-e=<expiry>]
                       -i=<issuer> -m=<algorithm> -p=<publicKey>
                       -s=<privateKey> -u=<subject>
                       [-o=<operation>] [-t=<token_to_be_verified>]
Generates a JWT token using the provided public and private keys
  -a, --audience=<audience>  Audience
  -c, --claims=<claims>      Custom claims Ex: claim:claim value
  -e, --expiry=<expiry>      Expiry in seconds
  -h, --help                 Show this help message and exit.
  -i, --issuer=<issuer>      Issuer
  -n, --noExpiry             No Expiry
  -p, --public=<publicKey>   Path to public key (in pem format)
  -o, --operation=<operation>
                             GENERATE or VERIFY 
  -s, --private=<privateKey> Path to private key (in pem format)
  -u, --subject=<subject>    Subject
  -t, --token=<token_to_be_verified>
                                 Token to be verified
  -V, --version              Print version information and exit.
```

##### Examples
* Using short options (Token without expiry)
```bash
./token-generator -a "user" -i "testapp" -p "public.pem" -s "private_key.pem" -u "mytestuser" -n \
    -c "test:test,test1:test1"  
```
* Using long options (Token without expiry)
```bash
./token-generator --audience "user" --issuer "testapp" --public "public.pem" \ 
    --private "private_key.pem" --subject "mytestuser" --noExpiry --claims "test:test,test1:test1" 
```
* Token with expiry (of 30 days)
```bash
./token-generator --audience "user" --issuer "testapp" --public "public.pem" \ 
    --private "private_key.pem" --subject "mytestuser" --expiry "2592000" --claims "test:test,test1:test1"
```

# resource-server
A simple OAuth2-compliant resource server, built as part of the Building Networked Systems Security (EP2520) course @ KTH. 

## Testing
In order to test, you will need a public/private pair of RSA keys. The keys for this project are encrypted using black box. 
Follow their instructions to add yourself to the keychain, and contact a current admin in order re-incrypt the file so that you can decrypt them. 

If you just want to test with your own local keys, then generate a private key and save it in a folder called `secrets` in the project dir. Using openssl, generate a private key (`rs.acme.com.pem`), generate a CSR and sign it. Save the certificate as `rs.acme.com.crt`. Also add the public CA cert and save it as `ca.crt`. Lastly, add the authorization servers public key (`auth.acme.com.pub.pem`) in order to be able to verify Json Web Tokens. 

Then, add `KEY_DIR=secrets` to a `.env` file, so that the app loads your keys. 

Start the server. The resource server is only useful if you have a corresponding authorisation server generating JWT tokens. 






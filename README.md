# JavaSecureChat
Simple Java chat program that uses Diffie Hellman key exchange
This example of a simple chat program that generates a server private/public key pair and a client private/public key pair,
then the client and server swap public keys, generate a common secret key from their private keys that is used to encryt and decrypt messages sent
each other.   This program mainly shows how to send the key objects via plain non SSL sockets.  Of course in the real world 
you could just use SSL sockets but this program is just used to illustrate the key exchange process from an academic perspective.


# sss
A Java key-value store for secret sharing

The PHP client library performs XOR based secret sharing and stores each piece on a separate server instance. Additionally, all pieces are AES encrypted so that they are useless without also hacking into the client.

While I originally considered this system to be reasonably secure, I wouldn't recommend anyone actually using it today for sensitive data as the client machine is an attack vector that bypasses the whole security system.

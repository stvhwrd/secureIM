# secureIM
[Java] Secure (encrypted) instant messaging between a client and server program.

## Description
IM software offers real-time text transmission over the network. Short messages are typically
transmitted bi-directionally between two parties. To simplify this assignment, we only consider
messaging between two parties: a server and a client. The server is supposed to be always up
and running. At any time, the client can initiate an IM session by sending an “open session”
message. After establishing the session, the client and server will be communicating by
exchanging text messages.
Before a session is established, the communicating parties (client and server) select (through a
GUI or a text interface) the security properties they require for their communication. The list of
selectable security properties should include:

1. **Confidentiality:** Encrypting messages sent from the client to the server and vice versa

2. **Integrity:** Checking integrity of the messages coming from client to the server and vice versa, such that no one in the middle can change or add some blocks to the exchanged messages

3. **Authentication:** Authenticating the origin of the messages coming from client or server in a way to make sure that messages have actually been sent by that party. If the client attempts to open a new session while the security properties selected in client and server are not the same, the session should be rejected with an appropriate error message.

We will use the Java Cryptography Architecture in our programs.

## Resources

### Java Cryptographic Architecture
> The Java platform strongly emphasizes security, including language safety, cryptography, public key infrastructure, authentication, secure communication, and access control.  The JCA is a major piece of the platform, and contains a "provider" architecture and a set of APIs for digital signatures, message digests (hashes), certificates and certificate validation, encryption (symmetric/asymmetric block/stream ciphers), key generation and management, and secure random number generation, to name a few. These APIs allow developers to easily integrate security into their application code.

* [Java Cryptography Architecture (JCA) Reference Guide](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)

### RMI
> The Java Remote Method Invocation (RMI) system allows an object running in one Java virtual machine to invoke methods on an object running in another Java virtual machine. RMI provides for remote communication between programs written in the Java programming language.

* [New Easy Tutorial for Java RMI using Eclipse](http://www.ejbtutorial.com/java-rmi/new-easy-tutorial-for-java-rmi-using-eclipse)

* [A Step by Step Implementation Tutorial for Java RMI](http://www.ejbtutorial.com/java-rmi/a-step-by-step-implementation-tutorial-for-java-rmi)

* [Java RMI Example : Simple Chat Program between Server and Client](http://www.ejbtutorial.com/java-rmi/java-rmi-example-simple-chat-program-between-server-and-client)

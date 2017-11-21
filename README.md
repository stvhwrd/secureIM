<strong>
<pre>
Welcome to                    ___ __  __
 ___  ___  ___ _   _ _ __ ___|_ _|  \/  |
/ __|/ _ \/ __| | | | '__/ _ \| || |\/| |
\__ \  __/ (__| |_| | | |  __/| || |  | |
|___/\___|\___|\__,_|_|  \___|___|_|  |_|

</pre>
</strong>

### [Java] Secure instant messaging between client and server.

This application was developed in Eclipse-Java 4.7.1 (Oxygen) and leverages the [Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html).  Code formatting and style is as per [google-java-format](https://github.com/google/google-java-format).

---

## 1. Introduction

The purpose of this application is to implement secure instant messaging between a client and server by allowing them to choose the security properties they require for their communication.  The three security properties that were implemented are confidentiality, integrity, and authentication.


## 2. Technical Details

The application secures bidirectional communication between a server and a client through the use of confidentiality, integrity, and authentication.

* **Confidentiality**
When confidentiality is selected, all messages between the client and server will be encrypted using a shared secret key. A new secret key is created by the client for each new session. To send the secret key to the server, the client encrypts it using the server’s public key and then signs it using the client’s private key so that both confidentiality and integrity are enforced. RSA is used for public/private key pairs and AES is used for symmetric keys

* **Integrity**
When integrity is selected, all messages are signed with the sender’s private key and verified by the receiver using the sender’s public key. SHA256 is used for signing messages.

* **Authentication**
When authentication is selected, mutual authentication must be established before messages can be exchanged. Passwords are hashed and then encrypted using the receiver’s public key and signed using the sender’s private key so that both confidentiality and integrity are maintained. The first time a user enters a password, the hashed password is saved by the receiver. In future sessions, the user must enter the same password in order for the connection to succeed and communication to commence. SHA256 is used for hashing passwords.


## 3. Compilation Steps
This section outlines the steps necessary to compile and run the program.

### 3.1 Compiling the Application
In a terminal on Windows, Mac or Linux, navigate to the project directory which contains the `src` directory, `bin` directory, and this pdf and compile the program:

```shell
javac -cp src -d bin src/ChatServer.java;
javac -cp src -d bin src/ChatClient.java;
```

### 3.2 Running the Application
Run the commands below to launch the application based on your operating system.

**Linux and Mac:**
In one terminal window, navigate to the project folder and launch the server instance:

```shell
java -Djava.security.policy=file:$PWD/src/security.policy -Djava.rmi.server.codebase=file:$PWD/bin/ -classpath $PWD/bin ChatServer;
```

In a second terminal window, navigate to the project folder and launch the client:

```shell
java -Djava.security.policy=file:$PWD/src/security.policy -Djava.rmi.server.codebase=file:$PWD/bin/ -classpath $PWD/bin ChatClient;
```

**Windows:**
In one terminal window, navigate to the project folder and launch the server instance:

```shell
java -Djava.security.policy=file:%cd%/src/security.policy -Djava.rmi.server.codebase=file:%cd%/bin/ -classpath %cd%/bin ChatServer;
```

In a second terminal window, navigate to the project folder and launch the client:

```shell
java -Djava.security.policy=file:%cd%/src/security.policy -Djava.rmi.server.codebase=file:%cd%/bin/ -classpath %cd%/bin ChatClient;
```


## 4. Usage

This section outlines the steps to use the application.

1. Launch a server instance and enter a username.

2. After entering a username, the server user will be prompted to choose their security settings.  They can type any combination of C, I, or A where each letter appears only once.  C stands for Confidentiality, I stands for Integrity, and A stands for Authentication.

3. After the server user chooses their security options, they will be notified that their chat remote  object is ready and will wait for a client to connect.

4. The client user connects following steps 1-3.
   >Note: It is important to note that the client must choose the same security options as the server.  If the client chooses security options which are different from the server, the console will notify the user that the options do not match and prompt the user to enter new security options.**

5. Once the client user accurately selects the same security options as the server user, the two users will be able to communicate with the security options implemented.

   (a) If Authentication is chosen, both the server user and the client user will have to input a password.  If it is the first time they are authenticating, the password they enter will be the password that is stored.  If they are a returning user, they will have to enter the correct password that corresponds to the username they entered previously.

   (b) If an incorrect password entered, the console will notify the user that the password was incorrect.

6. Once the secured connection is established, the server and client user can start to send each other messages.

7. The client user can disconnect from the chat at any time by typing /exit.


8. If a client user disconnects from the chat, the server user will be notified and asked to press the enter key to allow a new client user to connect.

 
## 5. Assumptions

This section outlines the assumptions made in the creation of this application.

* **Operating Systems**
Users are using either a Mac, Linux, or Windows operating system.

* **Java Version**
Users using the program are running Java 8<sup>+</sup>.

* **Connections**
There will be at any point in time no more than one server user and one client user connected to the server.

* **Public/Private Keys**
There is only one user on the server and one user on the client.  The server has a pair of public/private keys and the client has a different set of public/private keys which are generated by the application on the initial launch.

* **Access Control**
The client folder is only accessible by the client and the server folder is only accessible by the server.  This is assumed to be set and controlled by the operating system.



## Credit
All contributors are [listed on GitHub](https://github.com/stvhwrd/secureIM/graphs/contributors)

<!---**An offline password manager console application.**

**Security model:**
My security model is designed to ensure the confidentiality, integrity, and availability (CIA triad) of the application and user data.
I have embedded multiple lower and higher level security layers to ensure CIA.


**Confidentiality (ensure data is kept secret or private)**
- terminal/console is continously cleared, ensuring sensitive information cannot be access by scrolling up the terminal
- when logging in your password is not revealed
- user data is stored in hidden folders 
- user data is stored in parent directory instead of root directory

**Integrity (data is trustworthy and free from tampering)**
- stored user data is hashed or encrypted
- validation of login credentials
- user inputs are sanitized, to mitigate XSS attacks
- exponentially increasing wait times for login, to mitigate e.g. dictionary attacks
- logout after inactivity

**Availability (app must be functioning as it should. Valid users must have access to only their data (principle of least privilege)**
- all points listed under Integrity, except for point one, are also layers of protection against a breach in availability


**CIA triad**
- confidentiality: prevention of loss of access to resources and data
- Integrity: prevention of unauthorized modification of data
- Availability: prevention of unauthorized disclosure of data

![ing5erdiagram](https://github.com/leaand01/simplePasswordManager/blob/master/readmeAppDiagram.drawio.png)
-->


# An offline password manager console application.


## Run application
1.	Clone or fork the repository to your desired desktop location
2.	Unzip the folder ‘main.py’
3.	To start the SimplePasswordManager, open the unzipped folder ‘main’ and run the file main.exe 

![ing5erdiagram](https://github.com/leaand01/simplePasswordManager/blob/master/app_screenshots.png)


## SimplePasswordManager – Security Discussion

The Simple Password Manager is an offline CLI application, meaning it is installed on your hardware with no features to connect to the internet or being shared with other devices. 


## Threat Actors

-	People with physical access to your hardware
-	People with access to your hardware via remote desktop (whether authorized access or not)
-	Breakdown of hardware (not necessarily due to malicious actions. You could drop your pc or a glass of water in it.

The security measures of the application are implemented to mitigate the risk of an attacker with physical access to your hardware not being able to decrypt your password manger, also referred to as your vault.


## Security Layers

The application has implemented several layers of protection to mitigate the risk of compromising user privacy:
- You can only create a user with a strong username and password since these are harder to crack. The applications definition of a strong username/password must fulfill the following:
  - Must minimum be of length 9 and contain at least one small and big letter, one digit and one punctuation
  - Username and password cannot be identical
-	User inputs are sanitized, not allowing certain punctuations, in order to mitigate the risk of XSS
    - Remark: this is redundant as it is an offline application. Thus, if you have access to the application, you have access to the hardware and source code. This feature would only be applicable if it were an online application. I realized this after having implemented the feature so I choose to keep it, should it ever be upgraded to an online version. However, it can easily be removed by editing the banned variable in the config file, setting it equal to banned = [‘:’].
-	At login your entered password is not shown, mitigating the risk of anyone seeing your password by looking over your shoulder*
-	Continuously clearing the terminal to not reveal any sensitive information in the terminal history
-	Inactivity lockout set to 1minute. Increases confidentiality if you leave your pc unattended or forget to logout*
-	User data is stored in hidden folders located in the parent directory, instead of the app root directory. It makes them slightly less obvious to detect, unless you read the code, and mitigates the risk of the user accidentally deleting them
    - running the app from main.exe, the hidden folders are stored in this files parent directory
-	Usernames and passwords are not stored, introducing two elements of unknown that needs to be guessed in order to gain access to the user account
-	All text not sensitive to the user is saved in hashed format for obscured readability if the files are opened (e.g. column headers which are identical for all users)
-	All text sensitive to the user, i.e. the inputted vault data, is stored encrypted. The decryption key is not stored but must be generated in order to decrypt the vault, making it harder for an attacker to gain access as he can only generate the key by guessing the users login credentials, which were not stored.

'* The app could be installed and used on your work pc or laptop.


## Security model

The encryption and password/login protection features of the application includes the following: SHA512 hash, PBKDF2 and AES-256-GCM. Below is an overview of how and why these features have been implemented.
-	When creating a user, a unique random number (salt) is generated and stored
    - The salt value is used later in the PBDKF2 algorithm
    - The salt value is generated from the function ‘token_bytes’ from the Python Secrets module, which generates cryptographically strong random numbers. The strong randomness makes it appropriate for us to use as a salt value in PBKDF2.
    - The salt value is stored as the filename of the user’s vault file and .env file, the latter containing a unique tag and nonce used for AES decrypting of the vault file
      - The vault file and .env file are stored in two separate hidden folders in the parent directory
      - The text ‘tag’ and ‘nonce’ in the .env file is hashed by the powerful SHA512 hashing algorithm for obscured readability if opening the file
        - SHA512 is used as it is a powerful hash and more secure than SHA256. Further, since the application is offline the narrow compatibility of SHA512, compared to SHA256, is enough as it is compatible with Windows. If it were an online application then SHA256 could potentially be more applicable, c.f. https://cheapsslweb.com/blog/sha-256-vs-sha-512-key-encryption
-	The username, password, and salt value are used to generate a vault key using PBKDF2
    - The PBKDF2 algorithm is implemented because
      - It adds another random element to the vault key, instead of using only a strong hash of the username and password
      - It creates a strong hash and slows down potential brute force attacks
        - PBKDF2 is a key stretching method that makes it harder to guess the inputted username and password. The high number of iterations in the algorithm makes the hash computation slower, mitigating the risk of brute force attacks like dictionary attacks, since all brute force guesses of username and password needs to be hashed by the PBKDF2, where the high number of iterations slows down the brute force attempts. 
      - The vault key is used as the encryption key in the symmetric encryption algorithm AES-GCM. This encryption algorithm is used since it is highly secure and fast, c.f. https://cryptobook.nakov.com/symmetric-key-ciphers/popular-symmetric-algorithms
-	The AES-256-GCM encryption algorithm is used to encrypt and decrypt the vault.
    - Tag and nonce from the encryption is stored in the .env file.
-	When a user adds or deletes an item in his vault, the tag and nonce used for encryption/decryption is updated in the .env file. 


## Pitfalls

-	Data is stored locally on the hardware. Even if an attacker cannot read the files, he can delete them. Despite being stored in hidden folders in the parent directory the attacker can easily find them by reading the code which is accessible as he has access to the hardware itself. This poses a series threat again available in the CIA triad
-	If the hardware is stolen or breaks down your data is lost, and there is no backup (available issue)
-	If you forget your username or password you cannot login to your account as it is not possible to reset either of them
-	The password generator is rather simple and despite having introduced some randomness in the amount and placement of capital letters, digits and punctuations, the number of possible combinations could be brute forced with enough time and computing power.
    - Remark: my intent was to use the word lists form the NLTK Python library and then select random words from this large collection. Due to implementation issues, I settled with this minimalistic version illustrating the same purpose, but with a much more limited collection of words (c.f. the config file).
-	The applications definition of strength of a username and password is also rather simple, it could be improved such that e.g. substrings like ‘123’, ‘Password’, etc. would not be allowed. In other words, such that often uses phrases, numbers, sequences, etc. was not allowed.


## Security Discussion

Encryption wise data is stored securely according to the ‘Protect data at rest’ principle, since it has a secure encryption using a strongly hashed key which is not stored. An attacker would have to guess the username and password and find the right corresponding stored salt value before he would be able to generate the vault key (a process which is slowed down due to the high number of iterations in PBKDF2) and then attempt to decrypt a vault. However, finding the salt value is not the problem as it is the filename of the users vault file and .env file, and most likely the app would have 1 or few users, i.e. salt values, since it is an offline app.  What makes the encryption secure is the fact that login credentials are not stored, introducing 2 elements of unknown that needs to be guessed. Note, if the login credentials, or decrypted vault content, could be saved in a cache of a session this would be a major security flaw.

A weak point of the application is the fact that data is stored locally on the hardware and can be deleted, the hardware can get stolen, or break down. To mitigate the risk of deleting the hidden folders, the user could actively secure them by removing all permissions for all other users.

Another weak point is that no backups of the data are made. Users can of course clone the code and save the stored data on e.g. GitHub. This would also make it more applicable for multiple users. In this case one should bear in mind not to commit any cached data which may reveal sensitive data. On the other hand, this could serve as a backup of data.

Another weak point is that if you forget you login credentials you loose access to your account. Further, once created a user cannot delete his account unless he deletes the hidden folders. Thus, if more than one user was created this poses an issue and threat against availability for the remaining users.


## Application diagram
![ing5erdiagram](https://github.com/leaand01/simplePasswordManager/blob/master/new_appDiagram.drawio.png)



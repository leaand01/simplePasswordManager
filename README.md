**An offline password manager console application.**

Refer to CIA triad
confidentiality - prevention of loss of access to resources and data
Integrity - prevention of unauthorized modification of data
Availability - prevention of unauthorized disclosure of data

**Security model:**
My security model is designed to ensure the confidentiality, integrity, and availability (CIA triad) of the application and user data.
I have embedded multiple lower and higher level security layers to ensure CIA.

**Confidentiality (ensure data is kept secret or private)**
- terminal/console is continously cleared, ensuring sensitive information cannot be access by scrolling up the terminal
- (session related data is deleted upon exiting program - **not implemented. Do if have time**)
- when loggin in your password is not revealed
- user data is stored in hidden folders
- user data is hashed or key-encrypted
- user data is stored in parent directory instead of root directory

**Integrity (data is trustworthy and free from tampering)**
- 

**Availability (app must be functioning as it should. Valid users must have access to only their data (principle of least privilege)**





**An offline password manager console application.**

A diagram of the application is found here: https://github.com/leaand01/simplePasswordManager/blob/master/appDiagram.drawio
![ing5erdiagram](https://github.com/leaand01/simplePasswordManager/blob/master/readmeAppDiagram.drawio.png)

**Security model:**
My security model is designed to ensure the confidentiality, integrity, and availability (CIA triad) of the application and user data.
I have embedded multiple lower and higher level security layers to ensure CIA.


**Confidentiality (ensure data is kept secret or private)**
- terminal/console is continously cleared, ensuring sensitive information cannot be access by scrolling up the terminal
- (session related data is deleted upon exiting program - **not implemented. Do if have time**)
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




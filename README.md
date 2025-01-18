# pen-test-web-app
5. Important Notes:
This is a deliberately vulnerable web application for learning purposes.
Never deploy vulnerable applications like this in production environments.
Ensure you understand each vulnerability before attempting real-world penetration testing.

web app will be available at http://127.0.0.1:5000/.
Vulnerabilities 

SQL Injection: Try exploiting the SQL Injection on the login page.

Cross-Site Scripting (XSS): Test XSS by entering a script in the message field.

Insecure Direct Object Reference (IDOR)
Access http://127.0.0.1:5000/profile/1 for the first user.
Change the id in the URL to view other users' profiles, e.g., http://127.0.0.1:5000/profile/2.

Cross-Site Request Forgery (CSRF)
Exploit:
An attacker could send a malicious link to the logged-in user, for example:

html
Copy code
<img src="http://127.0.0.1:5000/change-password" />

Command Injection Input something like 127.0.0.1; ls into the ip field.
The attacker can run arbitrary commands by appending them after a semicolon (;).

Unrestricted File Upload An attacker could upload a PHP file or a web shell (if your server allows for such files to be executed)

Sensitive Data Exposure 
If an attacker gains access to the database or traffic is intercepted, the passwords are not encrypted, making them easy to compromise.
Security Misconfiguration
ploit:
When an attacker triggers an error in the application, they might receive detailed debug information, including stack traces, which could help them identify vulnerabilities in your code or server setup.

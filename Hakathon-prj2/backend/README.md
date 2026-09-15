# PinIt Security & Antivirus Analysis Backend

A high-performance, asynchronous, multi-purpose security analysis engine and REST API designed to inspect uploaded files and URLs for malware, viruses, phishing, suspicious behavior, and advanced security threats.

---

## Architecture Overview

```
                      +-----------------------------------+
                      |   Client Application (PinIt UI)   |
                      +-----------------+-----------------+
                                        |
                                        v
+---------------------------------------------------------------------------------+
|                       PinIt API Gateway (Port 4000)                             |
|                                                                                 |
|   +-------------------+   +--------------------+   +------------------------+   |
|   |  CORS & Helmet    |-->|  Rate Limiting     |-->|  JWT / API Key Auth    |   |
|   |  Security Headers |   |  (express-rate)    |   |  (RBAC Middleware)     |   |
|   +-------------------+   +--------------------+   +------------------------+   |
|                                                                                 |
|   +-------------------+   +--------------------+   +------------------------+   |
|   |  Upload Sanitizer |-->|  Audit Logging     |-->|  OpenAPI Swagger UI    |   |
|   |  (Multer + Safe)  |   |  (Winston Masked)  |   |  (/api/docs)           |   |
|   +-------------------+   +--------------------+   +------------------------+   |
+---------------------------------------+-----------------------------------------+
                                        |
                         +--------------v--------------+
                         |     Scan Job Dispatcher     |
                         +--------------+--------------+
                                        |
                                        v
                         +-----------------------------+
                         |      Asynchronous Queue     |
                         |  (BullMQ + Redis / Memory)  |
                         +--------------+--------------+
                                        |
               +------------------------+------------------------+
               |                                                 |
               v                                                 v
+-----------------------------+                   +-----------------------------+
|     File Analysis Worker    |                   |     URL Analysis Worker     |
|                             |                   |                             |
|  * Multi-Hash Engine        |                   |  * Normalization Engine     |
|    (SHA256, SHA1, MD5)      |                   |  * SSRF Shield              |
|  * Magic Bytes & MIME Check |                   |    (Blocks RFC1918/Metadata)|
|  * Static Code Analyzer     |                   |  * Domain & Homoglyph Check |
|    (Macros, PS, Eval)       |                   |  * Phishing Heuristics      |
|  * Archive Zip-Bomb Guard   |                   |  * Safe Redirect Tracer     |
|  * ClamAV Antivirus Daemon  |                   |  * Threat Intel Provider    |
|  * Threat Intel Cache       |                   |    (VirusTotal / Database)  |
+--------------+--------------+                   +--------------+--------------+
               |                                                 |
               +------------------------+------------------------+
                                        |
                                        v
                         +-----------------------------+
                         |      Result Aggregator      |
                         |  * Normalized Risk Score    |
                         |  * Categorization (0-100)   |
                         |  * Safe Factor Extraction   |
                         |  * Action Recommendations   |
                         +--------------+--------------+
                                        |
                                        v
                         +-----------------------------+
                         |    Relational Database      |
                         |  (Prisma + SQLite/Postgres) |
                         +-----------------------------+
```

---

## 1. Quick Start

The backend is engineered to run **zero-dependency out-of-the-box** in local development mode using SQLite and an in-memory asynchronous worker queue, or in full **production scale** using Docker, Redis, and ClamAV.

### Option A: Local Zero-Dependency Mode (Fastest)

1. **Navigate to the backend folder**:
   ```bash
   cd backend
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Initialize the local database**:
   ```bash
   npx prisma db push
   ```

4. **Start the development server**:
   ```bash
   npm run dev
   ```

5. The API will be active at:
   - **API Root**: `http://localhost:4000/api/v1`
   - **Health Check**: `http://localhost:4000/api/v1/health`
   - **Interactive Swagger Docs**: `http://localhost:4000/api/docs`

---

### Option B: Docker Compose (Full Production Cluster)

Includes the API server, dedicated worker node, PostgreSQL, Redis, and ClamAV antivirus daemon:

```bash
cd backend
docker-compose up --build -d
```

Check cluster status:
```bash
docker-compose ps
```

Stop the cluster:
```bash
docker-compose down
```

---

## 2. API Endpoint Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | Public | System health, database connectivity, and queue mode |
| `GET` | `/api/v1/statistics` | Public | Aggregated counts of total, clean, suspicious, and malicious scans |
| `POST` | `/api/v1/auth/register` | Public | Create a user account (returns JWT token and API Key) |
| `POST` | `/api/v1/auth/login` | Public | Authenticate user and receive JWT session token |
| `POST` | `/api/v1/files/scan` | Optional | Upload a file (`multipart/form-data`) for asynchronous analysis |
| `GET` | `/api/v1/files/scan/:id` | Optional | Retrieve file scan results, metadata, hashes, and detections |
| `POST` | `/api/v1/urls/scan` | Optional | Submit a URL (`application/json`) for security analysis |
| `GET` | `/api/v1/urls/scan/:id` | Optional | Retrieve URL scan results, redirect history, and threat signals |
| `GET` | `/api/v1/scans` | Optional | Paginated list of all scan records (`?page=1&limit=20&type=FILE`) |
| `GET` | `/api/v1/scans/:id` | Optional | Detailed scan record by UUID |
| `DELETE` | `/api/v1/scans/:id` | Admin | Delete a scan record and cascade its detections |

---

## 3. How Security Analysis Works

### A. File Analysis Pipeline

1. **Upload & Quarantine**:
   - Files are validated against the 25MB maximum limit.
   - File names are sanitized with UUID tokens to prevent directory traversal (`../../`).
   - Files are stored in an unprivileged temporary directory with restrictive permissions.
   - Files are **never executed directly** under any circumstances.
2. **Multi-Hash Computation**:
   - Computes **SHA-256**, **SHA-1**, and **MD5** in a single high-efficiency streaming pass.
3. **Magic Byte & MIME Verification**:
   - Reads the leading byte signatures (e.g., `4D 5A` for PE executables, `50 4B 03 04` for ZIP/DOCX, `25 50 44 46` for PDF).
   - Detects **file extension spoofing** (e.g., an executable named `document.pdf.exe` or `invoice.png`).
4. **Deep Static Analysis**:
   - **Office Documents**: Scans for VBA macros (`word/vbaProject.bin`, `AutoOpen`, `Workbook_Open`).
   - **Scripts & Shells**: Scans for dangerous commands, encoded PowerShell (`-enc`, `powershell.exe -w hidden`), `certutil -decode`, `eval()` in JavaScript, and bash download-and-execute pipes (`curl | sh`).
   - **Archives**: Parses ZIP directory headers to calculate compression ratios (detecting 42.zip-style zip bombs) and finds hidden nested executables or scripts.
5. **ClamAV Antivirus Daemon**:
   - Streams bytes over TCP `INSTREAM` to ClamAV on port 3310.
   - If ClamAV daemon is unreachable, the engine gracefully activates internal signature heuristics (including EICAR test file validation).
6. **Secure Deletion**:
   - Temporary upload files are securely removed immediately after scan completion.

### B. URL Analysis Pipeline

1. **Normalization**:
   - Parses URLs according to WHATWG standard, handles protocol lowercasing, removes default ports (80/443), and cleans whitespace.
2. **SSRF Guard**:
   - Resolves domains to IPv4 and IPv6 addresses.
   - **Strictly blocks** connections to private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local, and cloud instance metadata services (`169.254.169.254`).
3. **Homoglyph & Punycode Detection**:
   - Flags internationalized domain names (IDN `xn--`) used in homograph attacks to impersonate legitimate domains with Cyrillic/Greek lookalike glyphs.
4. **Phishing & Brand Impersonation**:
   - Detects subdomains attempting to spoof known institutions (e.g., `paypal.com.account-verify.xyz`).
   - Evaluates high-risk Top-Level Domains (`.top`, `.xyz`, `.buzz`, `.racing`).
   - Flags suspicious query and path credential triggers (`verify`, `wallet-connect`, `login`, `suspended`).
5. **Isolated HTTP Probing**:
   - Issues sandboxed HTTP probes with strict 5-second timeouts and redirect limit guards.
   - Validates each hop in the redirect chain against SSRF rules to prevent open-redirect exploitation.

---

## 4. Threat Scoring & Aggregation Model

The system aggregates all detection indicators into an objective 0–100 risk score:

| Risk Category | Score Range | Description | Typical Triggers |
|---|---|---|---|
| **SAFE** | `0 - 14` | No known threat indicators or malicious signals. | Known clean file, verified HTTPS domain. |
| **LOW_RISK** | `15 - 34` | Minor anomalies with low probability of harm. | Unencrypted HTTP, minor uncommon file extension. |
| **SUSPICIOUS** | `35 - 69` | Suspicious behavioral patterns requiring user caution. | High-risk TLD, obfuscated scripts, macro containers. |
| **HIGH_RISK** | `70 - 89` | Strong indicators of malicious or deceptive intent. | Brand spoofing, archive with hidden executable, homoglyph attack. |
| **MALICIOUS** | `90 - 100` | Confirmed malware signature or exploit attempt. | ClamAV positive match, EICAR test string, SSRF exploit attempt. |
| **UNKNOWN** | `N/A` | Scan failed or timed out during processing. | Corrupted input, unhandled parser fault. |

---

## 5. Environment Variables (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `4000` | HTTP port for the Express API |
| `NODE_ENV` | `development` | Runtime mode (`development` or `production`) |
| `DATABASE_URL` | `file:./dev.db` | Prisma database connection string |
| `REDIS_URL` | *(empty)* | Optional Redis URL for BullMQ. Uses memory queue if empty. |
| `CLAMAV_HOST` | `localhost` | ClamAV daemon hostname |
| `CLAMAV_PORT` | `3310` | ClamAV daemon TCP port |
| `JWT_SECRET` | *(string)* | Secret used to sign authentication tokens |
| `API_KEY_SECRET` | *(string)* | Salt used for user API key generation |
| `SCAN_FILE_MAX_SIZE_MB` | `25` | Maximum allowed file upload size in megabytes |
| `RATE_LIMIT_WINDOW_MS` | `900000` | Rate limiter sliding window (15 minutes) |
| `RATE_LIMIT_MAX` | `100` | Maximum requests per IP per window |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional external threat intelligence API key |

---

## 6. Running Tests

The test suite validates file scanning, hash generation, magic byte verification, static macro and script analysis, URL heuristics, SSRF blocking, ClamAV integration, result aggregation, and end-to-end API workflows.

```bash
npm test
```

To run with coverage or UI:
```bash
npx vitest run
```

---

## 7. Future Roadmap & Dynamic Analysis Sandbox

1. **Dynamic Sandbox Worker (Phase 2)**:
   - Run suspicious executables in disposable QEMU/KVM or gVisor microVMs with simulated network environments (INetSim).
   - Capture API hooks, registry modifications, process injection, and dropped payloads.
2. **YARA Rules Engine**:
   - Mount custom, community-maintained YARA rule repositories for specialized ransomware and APT detection.
3. **Advanced Threat Intel Integrations**:
   - Native connectors for AbuseIPDB, AlienVault OTX, and URLhaus.

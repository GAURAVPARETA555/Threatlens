# ThreatLens: Easy Local Testing Guide

This guide shows how to start ThreatLens and test the complete workflow from the browser:

1. Start the frontend, Django backend, and ML service.
2. Log in as an administrator.
3. Ingest security telemetry.
4. Run hybrid rule + ML analysis.
5. Triage the generated alert.
6. Queue an asset scan.
7. Review metrics and export a report.

ThreatLens analyzes **simulated security telemetry**. The test payloads below are strings submitted to your local application; they do not execute an attack against a real website.

## 1. Important local links

Keep these links available while testing:

| Purpose | Link |
|---|---|
| ThreatLens console | [http://localhost:5173](http://localhost:5173) |
| Login page | [http://localhost:5173/login](http://localhost:5173/login) |
| Event stream | [http://localhost:5173/events](http://localhost:5173/events) |
| Detections | [http://localhost:5173/detections](http://localhost:5173/detections) |
| Alerts queue | [http://localhost:5173/alerts](http://localhost:5173/alerts) |
| Asset scans | [http://localhost:5173/scans](http://localhost:5173/scans) |
| Reports | [http://localhost:5173/reports](http://localhost:5173/reports) |
| Django API | [http://127.0.0.1:8000](http://127.0.0.1:8000) |
| ML prediction endpoint | [http://127.0.0.1:8001/predict/](http://127.0.0.1:8001/predict/) |

The ML URL is a POST endpoint and normally does not display a useful page when opened directly.

## 2. Start the application on Windows

### Recommended: one-click startup

From the repository folder:

```text
C:\Users\Akshat\Desktop\ThreatLens\Threatlens
```

Double-click [start_all.bat](./start_all.bat).

This opens separate command windows for:

- Django backend on port `8000`
- Mock ML service on port `8001`
- React/Vite frontend on port `5173`

The browser should open automatically at [http://localhost:5173](http://localhost:5173).

Keep all three command windows running while testing. To stop the application, close those command windows.

### Manual startup

Use three separate PowerShell or Command Prompt windows.

#### Window 1: Django backend

```powershell
cd C:\Users\Akshat\Desktop\ThreatLens\Threatlens\backend
.\env\Scripts\activate
python manage.py runserver 127.0.0.1:8000
```

#### Window 2: Mock ML service

```powershell
cd C:\Users\Akshat\Desktop\ThreatLens\Threatlens\backend
.\env\Scripts\activate
python mock_ml.py
```

You should see that the service is running at:

```text
http://127.0.0.1:8001/predict/
```

#### Window 3: Frontend

```powershell
cd C:\Users\Akshat\Desktop\ThreatLens\Threatlens\frontend
npm run dev
```

Open [http://localhost:5173/login](http://localhost:5173/login).

## 3. Sign in

Use the existing administrator account:

```text
Username: admin
Password: Password123!
```

After signing in, confirm:

- The page changes to the Overview dashboard.
- The top-right account menu shows `ADMIN`.
- The left navigation contains Overview, Events, Detections, Alerts, Scans, and Reports.
- The sidebar shows `HYBRID ENGINE ONLINE`.

If the login page does not load, verify that the frontend is running. If the page loads but data does not appear, verify that the backend is running.

## 4. Test case 1: SQL injection telemetry

This is the easiest complete test because the default form already contains a SQL injection-style sample.

### Step 1: Open Events

Open [http://localhost:5173/events](http://localhost:5173/events), or click **Events** in the left navigation.

### Step 2: Ingest the sample event

Click **Ingest Event**. Leave the default values as they are:

| Field | Value |
|---|---|
| Source IP | `192.168.1.105` |
| Endpoint | `/admin/login` |
| Request rate | `65` |
| Failed logins | `12` |
| Special characters | `8` |

The raw JSON payload should contain:

```json
{
  "user_agent": "Mozilla/5.0",
  "param": "' OR '1'='1"
}
```

Click **Submit Telemetry Event**.

Expected result:

- The dialog closes.
- A new event appears in the table.
- The event has an ID such as `#1`, `#2`, or another next available ID.

### Step 3: Analyze the event

Click **Analyze** on the event you just created.

Expected result:

- The browser opens a URL similar to `/detections/2`.
- The detection page shows `Rule Signal: TRIGGERED`.
- Evidence includes `[SQLI-002] Boolean SQL manipulation pattern`.
- ML intent is `MALICIOUS`.
- ML confidence is `95.0% (0.9500)`.
- Risk is `87.5 / 100`.
- Severity is `CRITICAL`.

The displayed calculation is:

```text
((0 × 0.5) + (0.95 × 0.5)) × 100 = 87.50
```

The rule engine reports the signature match separately from its confidence value. In this project, the rule confidence is intentionally uncalibrated and remains `0.00`; the deterministic rule severity still contributes a severity floor.

### Step 4: Check the alert

Open [http://localhost:5173/alerts](http://localhost:5173/alerts).

You should see an alert associated with the new detection. Its initial status is `OPEN`.

Change the dropdown to:

```text
INVESTIGATING
```

Expected result:

- The status changes immediately in the table.
- Refreshing the page keeps the new status.
- The Overview page shows the alert as `INVESTIGATING`, not as an open alert.

You can later change it to `RESOLVED`. A resolved alert receives a resolution timestamp.

## 5. Test case 2: stronger SQL injection sample

For a separate event, return to [http://localhost:5173/events](http://localhost:5173/events), click **Ingest Event**, and use:

```text
Source IP: 203.0.113.10
Endpoint: /products
Request rate: 20
Failed logins: 0
Special characters: 5
```

Use this JSON payload:

```json
{
  "query": {
    "q": "' UNION SELECT username, password FROM users --"
  }
}
```

Click **Submit Telemetry Event**, then **Analyze** the new event.

Expected result:

- `Rule Signal: TRIGGERED`
- Attack type similar to `SQL Injection`
- Evidence containing `SQLI-001`, `SQLI-003`, or `SQLI-004`
- A high or critical result
- An alert in the Alerts queue

## 6. Test case 3: benign traffic

This confirms that normal traffic is not automatically treated as an attack.

Ingest this event:

```text
Source IP: 192.0.2.20
Endpoint: /search
Request rate: 2
Failed logins: 0
Special characters: 0
```

Payload:

```json
{
  "query": {
    "q": "how to use python"
  }
}
```

Analyze it.

Expected result:

- The rule signal should be clean.
- No high or critical alert should be created by the rule engine.
- The mock ML service may still report `malicious` because it is deliberately configured as a deterministic test service. This is useful for testing the hybrid risk calculation, but it is not a production ML prediction.

## 7. Other safe simulated attack payloads

Create one new event per test. Analyze each event only once because every analysis creates a new detection.

### Cross-site scripting (XSS)

```json
{
  "query": {
    "q": "<script>alert('xss')</script>"
  }
}
```

Suggested endpoint: `/search`

### Path traversal

```json
{
  "query": {
    "file": "../../../../etc/passwd"
  }
}
```

Suggested endpoint: `/download`

### Server-side request forgery (SSRF)

```json
{
  "query": {
    "url": "http://169.254.169.254/latest/meta-data/"
  }
}
```

Suggested endpoint: `/proxy`

### Command injection

```json
{
  "query": {
    "command": "id; whoami"
  }
}
```

Suggested endpoint: `/tools/run`

These are only strings inside telemetry JSON. ThreatLens should inspect and classify them; it should not execute them.

## 8. Test asset scanning

The scan feature currently records scan requests and their lifecycle state. It does not perform a real network scan.

For a safe public test host, use [scanme.nmap.org](https://scanme.nmap.org/), which is provided by the Nmap project for testing Nmap and related tools. Follow the site's usage rules and do not use it for aggressive or unauthorized testing.

1. Open [http://localhost:5173/scans](http://localhost:5173/scans).
2. Click **Launch Scan**.
3. Enter:

   ```text
   scanme.nmap.org
   ```

4. Click **Initiate Scan**.
5. Confirm that a row appears with status `PENDING`.
6. Click **Inspect** to view the scan record.

You can also use a reserved documentation IP such as `192.0.2.10` if you only want to test the form and database workflow without identifying a real host.

## 9. Test reports and PDF export

Open [http://localhost:5173/reports](http://localhost:5173/reports).

Review:

- Events recorded
- Detections evaluated
- Average risk score
- Malicious predictions
- Saved report archive

Click **Print / Export PDF** to open the browser print dialog. Choose **Save as PDF**.

The **Generate AI Executive Report** button requires a Groq API key. Leave that button for the next setup phase unless you already have a key configured.

Groq console link: [https://console.groq.com/keys](https://console.groq.com/keys)

Never paste a Groq key into the frontend, a chat message, a screenshot, or a committed file.

### Groq incident explanation

This feature analyzes one detection and returns:

- A plain-language explanation
- Possible impact
- Recommended mitigation steps

1. Open [http://localhost:5173/detections](http://localhost:5173/detections).
2. Select a detection that has a high or critical risk score.
3. Open the detection detail page.
4. Find the **GROQ LLM INCIDENT ANALYSIS** card.
5. Click **Generate Explanation**.
6. Wait for the card to replace the empty state with the generated analysis.

The explanation, impact, and mitigation text are saved to the database. When you reopen the same detection later, ThreatLens loads the cached explanation instead of calling Groq again.

### Groq executive report

This feature summarizes the current telemetry and detections into:

- An executive summary
- A threat assessment
- Key findings
- A risk assessment
- Defensive recommendations

1. Open [http://localhost:5173/reports](http://localhost:5173/reports).
2. Confirm that the page shows the current event and detection totals.
3. Click **Generate AI Executive Report**.
4. Wait while Groq analyzes the aggregated security statistics.
5. Select the report labeled **AI EXECUTIVE** in the Saved Report Archive.
6. Review the generated sections in the report panel.
7. Use **Print / Export PDF** if you want a PDF copy.

Every generated AI report is saved in the Reports table. Generating it again creates another report; it does not overwrite the previous report.

### Verifying Groq through the API

After logging in and obtaining an access token, replace `DETECTION_ID` with a real detection ID:

```powershell
$headers = @{
  Authorization = "Bearer $($login.access)"
}

$detectionId = 6

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/ai/explain/$detectionId/" `
  -Headers $headers
```

Generate an executive report through the API:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/reports/ai-summary/" `
  -Headers $headers
```

The incident endpoint should return `explanation`, `impact`, and `recommended_mitigation`. The report endpoint should return `summary_json.ai_analysis`.

## 10. Optional API verification with PowerShell

The browser is the recommended way to test the product. These commands are useful when diagnosing a UI problem.

### Get a token

```powershell
$login = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/auth/login/" `
  -ContentType "application/json" `
  -Body (@{
    username = "admin"
    password = "Password123!"
  } | ConvertTo-Json)

$headers = @{
  Authorization = "Bearer $($login.access)"
}
```

### List events

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://127.0.0.1:8000/api/events/list/?page_size=10" `
  -Headers $headers
```

The response should contain:

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": []
}
```

### Ingest an event through the API

```powershell
$event = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/events/" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body (@{
    source_ip = "203.0.113.10"
    endpoint = "/products"
    request_rate = 20
    failed_login_count = 0
    special_char_count = 5
    raw_payload = @{
      query = @{
        q = "' UNION SELECT username, password FROM users --"
      }
    }
  } | ConvertTo-Json -Depth 6)

$event
```

### Analyze that event

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/detections/analyze/" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body (@{
    event_id = $event.id
  } | ConvertTo-Json)
```

## 11. Automated verification

These checks do not require the browser services to be running.

### Backend integration tests

```powershell
cd C:\Users\Akshat\Desktop\ThreatLens\Threatlens\backend
.\env\Scripts\python.exe manage.py test security
```

Expected result:

```text
Ran 7 tests
OK
```

### CyberSecurity detection tests

```powershell
cd C:\Users\Akshat\Desktop\ThreatLens\Threatlens
$env:PYTHONPATH = "C:\Users\Akshat\Desktop\ThreatLens\Threatlens\CyberSecurity"
.\backend\env\Scripts\python.exe -m unittest discover -s CyberSecurity\Tests
```

Expected result:

```text
Ran 131 tests
OK
```

### Frontend build

```powershell
cd C:\Users\Akshat\Desktop\ThreatLens\Threatlens\frontend
npm run build
```

Expected result:

```text
built successfully
```

## 12. Troubleshooting

### The page cannot be opened

Check that port `5173` is listening and that the frontend command window is still running.

### The dashboard loads but shows no data

Check that the Django backend is running on port `8000`, then refresh the page.

### Analysis fails

Check that the mock ML service is running on port `8001`. The Django backend calls:

```text
http://127.0.0.1:8001/predict/
```

### A previous test is still visible

That is expected. Events and detections are stored in the local SQLite database. Use a new event for each test and record its ID.

### Duplicate detections appear

Clicking **Analyze** more than once for the same event creates more detections. Analyze each event once during normal testing.

### Report AI generation fails

The AI report requires `GROQ_API_KEY` in `backend/.env`. A missing or invalid key is expected to prevent the Groq feature from working; the local telemetry and PDF features do not require it.

## 13. Safe testing rules

- Test only this local application or systems you own or have explicit permission to test.
- Use simulated payloads as shown in this guide.
- Do not send these payloads to public websites.
- Do not perform real scans against arbitrary IP addresses or domains.
- Do not commit `backend/.env` or share API keys.
- Treat detection results as signals for investigation, not proof that a real system was compromised.

For the implementation-level detector tests, see [CyberSecurity/Docs/security_testing.md](./CyberSecurity/Docs/security_testing.md).

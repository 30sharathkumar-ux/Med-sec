# RAKSHA — Real Browser Test Report

## Status: **NOT VERIFIED**

- **Target URL:** `http://127.0.0.1:8080` (server verified running on `task-1153`).
- **Browser Automation Availability:**
  - `playwright`: `NOT_INSTALLED`
  - `selenium`: `NOT_INSTALLED`
  - `chrome_devtools` MCP: Failed to connect (`Could not find DevToolsActivePort for chrome at C:\Users\Darwin\AppData\Local\Google\Chrome\User Data\DevToolsActivePort`).
- **Result:** Live headless/GUI browser navigation, console-error inspection, and `1440px` / `768px` / `375px` viewport screenshots could not be executed in this environment and are therefore honestly marked **NOT VERIFIED** rather than simulated.
- **What WAS Verified:** All backend routes backing the UI (`/`, `/styles.css`, `/app.js`, `/api/overview`, `/api/datasets`, `/api/datasets/inspect`, `/api/datasets/upload`, `/api/runs/start`, `/api/runs/status`, `/api/runs/select`, `/api/files`, `/api/linkage`, `/api/reports/download`) were verified directly via HTTP requests in `api_security_test.py` (`14/14` passed).

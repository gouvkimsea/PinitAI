# Pinit AI — Browser Extension (Chrome, Edge, Brave, Opera, Firefox)

The **Pinit AI Browser Extension** provides real-time client-side protection against phishing URLs, malicious downloads, brand impersonation, and fraudulent social engineering messages directly within the browser.

---

## Key Capabilities

1. **Active Tab Instant URL Scanner**: Reads the active browser tab URL via Chrome Tabs API and delivers an instant 0–100 threat score with actionable risk categorization.
2. **On-the-Fly Message Analyzer**: Allows pasting suspicious SMS, Telegram job offers, or payment requests directly into the popup.
3. **Background Real-Time Link Guard (`content.js`)**: Passively monitors link hovers on visited web pages, instantly displaying an alert tooltip if a link routes to a raw numeric IP address, high-abuse TLD (`.tk`, `.xyz`, `.top`, `.click`), or known bank/brand look-alikes.
4. **Multi-Tier Failover Resilience**:
   - **Tier 1:** Python FastAPI AI Engine (`http://127.0.0.1:8000`)
   - **Tier 2:** Node.js Express API Server (`http://localhost:4000/api/v1`)
   - **Tier 3:** Built-in offline heuristic guard (guarantees protection even if local servers are offline).

---

## How to Install & Test (Developer Mode)

### Step 1: Open Extensions Page
- In **Google Chrome**: Navigate to `chrome://extensions`
- In **Microsoft Edge**: Navigate to `edge://extensions`
- In **Brave**: Navigate to `brave://extensions`

### Step 2: Enable Developer Mode
- Turn on the **Developer mode** toggle in the top-right corner.

### Step 3: Load the Unpacked Extension
- Click the **Load unpacked** button.
- Select the `browser_extension` folder located inside this project:
  ```text
  d:\prj 2\browser_extension
  ```

### Step 4: Pin to Browser Toolbar
- Click the Extensions puzzle icon in your browser toolbar.
- Pin **Pinit AI** for instant 1-click access.

---

## How to Package for Web Store Deployment

To submit to the [Chrome Web Store](https://chrome.google.com/webstore/devconsole) or [Microsoft Edge Add-ons Dashboard](https://partner.microsoft.com/dashboard/microsoftedge):

1. Compress the contents of the `browser_extension/` directory into a `.zip` file:
   - `manifest.json`
   - `popup.html`
   - `popup.js`
   - `content.js`
   - `logo.png`
   - `icon48.png`
   - `icon128.png`
2. Upload the `.zip` archive directly in the Developer Console.

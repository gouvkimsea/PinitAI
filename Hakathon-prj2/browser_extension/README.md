# ScamCheck AI — Browser Extension (Chrome, Edge, Brave, Firefox)

This extension brings **real-time scam protection** directly to your browser.

## Features
- **Quick Scan Popup**: Check active tab URL or paste suspicious messages with 1 click.
- **Real-Time Link Hover Warning**: Automatically inspects links on webpages and alerts you if hovering over raw numeric IP hosts, known look-alikes, or high-risk scam TLDs (`.tk`, `.xyz`, `.top`, etc.).
- **Direct API Integration**: Communicates with the ScamCheck AI Engine at `http://127.0.0.1:8000`.

## Installation (Developer Mode)

1. Open your Chromium-based browser (Google Chrome, Microsoft Edge, Brave, Opera).
2. Navigate to `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked**.
5. Select the `browser_extension` folder from this repository:
   ```text
   Hakathon-prj2/browser_extension
   ```
6. The **ScamCheck AI** icon will now appear in your browser toolbar!

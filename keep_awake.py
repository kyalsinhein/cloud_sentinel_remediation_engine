from playwright.sync_api import sync_playwright

URL = "https://YOUR-APP.streamlit.app"

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(URL, wait_until="domcontentloaded")
    # If the app is asleep, click the wake-up button
    try:
        page.get_by_role("button", name="Yes, get this app back up!").click(timeout=15000)
    except Exception:
        pass
    # Wait for the app title so a real session is established
    page.wait_for_selector("text=Cloud Sentinel Remediation Engine", timeout=90000)
    page.wait_for_timeout(5000)
    browser.close()

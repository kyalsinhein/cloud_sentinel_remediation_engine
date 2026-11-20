from playwright.sync_api import sync_playwright

URL = "https://cloudsentinelremediationengine-57tvbxmbeq4qlp5yvmp4gs.streamlit.app/"   
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(URL, wait_until="domcontentloaded", timeout=60000)

    # If the app is asleep, click the wake-up button
    try:
        page.get_by_role("button", name="Yes, get this app back up!").click(timeout=15000)
        print("App was asleep - wake button clicked")
        page.wait_for_timeout(60000)   # give it time to boot
    except Exception:
        print("No wake button (app already awake)")

    # The app renders inside an iframe, so search every frame
    found = False
    for _ in range(12):                # up to ~60 seconds
        for frame in page.frames:
            try:
                if frame.get_by_text("Cloud Sentinel").count() > 0:
                    found = True
                    break
            except Exception:
                pass
        if found:
            break
        page.wait_for_timeout(5000)

    print("App content found:", found)
    page.wait_for_timeout(5000)
    page.screenshot(path="shot.png")
    browser.close()

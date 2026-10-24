"""Real-browser test of the UI with Playwright: loads the page, runs a full sweep,
verifies progress/rendering/export, and takes screenshots."""
import sys, time, json
from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8000/"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "example.com"
SHOT = "/home/user/osint-console/docs/screenshot-sweep.png"

errors, logs = [], []
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    page = b.new_page(viewport={"width": 1440, "height": 980})
    page.on("console", lambda m: (logs.append((m.type, m.text)),
                                  errors.append(m.text) if m.type == "error" else None))
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="networkidle", timeout=60000)
    time.sleep(1.5)

    # 1) shell rendered?
    assert page.locator("#title").inner_text() == "المسح الشامل", "title mismatch"
    mods = page.locator("#nav .item").count()
    print(f"✓ الصفحة حُمّلت · أزرار الوحدات في القائمة: {mods}")
    health = page.locator("#stHealth").inner_text()
    print(f"✓ حالة الاتصال: {health}")
    assert "متصل" in health

    # 2) start the sweep
    page.fill("#q", TARGET)
    page.click("#go")
    print("✓ بدأ المسح…")

    # 3) wait for completion (banner shows 'انتهى')
    start = time.time()
    finished = False
    while time.time() - start < 180:
        pill = page.locator("#statePill").inner_text()
        if pill.startswith("انتهى") or "خطأ" in pill:
            finished = True
            break
        time.sleep(1)
    assert finished, "sweep did not finish"
    elapsed = time.time() - start

    rows = page.locator("#sres .res").count()
    ok_rows = page.locator("#sres .res .hd .badge.b-ok").count()
    err_rows = page.locator("#sres .res .hd .badge.b-err").count()
    skip_rows = page.locator("#sres .res .hd .badge.b-skip").count()
    print(f"✓ انتهى المسح في {elapsed:.1f}s · صفوف={rows} ناجحة={ok_rows} فاشلة={err_rows} لا-تنطبق={skip_rows}")
    print(f"✓ شريط التقدم: {page.locator('#sBar').get_attribute('style')}")
    print(f"✓ الملخص: {page.locator('#sDone').inner_text()} · ناجحة {page.locator('#sOk').inner_text()} · فاشلة {page.locator('#sErr').inner_text()}")

    # 4) content actually rendered (tables/values, not just spinners)
    body = page.locator("#sres").inner_text()
    KIND = {"example.com": ["DNS", "RDAP", "شهاد", "WHOIS"],
            "torvalds": ["المستخدم", "GitHub"],
            "8.8.8.8": ["IP", "الجغرافيا"]}.get(TARGET, [])
    for token in KIND:
        assert token in body, f"missing section {token} in rendered output"
    assert page.locator("#sres .res").count() >= 5, "too few module rows rendered"
    tables = page.locator("#sres table").count()
    assert "[object Object]" not in body, "UI rendered a raw object"
    assert "undefined" not in body.replace("undefined-", ""), "UI rendered undefined"
    print(f"✓ جداول معروضة: {tables} · حجم النص المعروض: {len(body)} حرف")

    # 5) export buttons exist and work
    page.click("#openAll")
    with page.expect_download() as dl:
        page.click("#expJson")
    path = dl.value.path()
    data = json.load(open(path, encoding="utf-8"))
    print(f"✓ تصدير JSON: {len(data.get('results', {}))} وحدة · حجم {len(open(path,'rb').read())} بايت")
    with page.expect_download() as dl2:
        page.click("#expHtml")
    html_path = dl2.value.path()
    html = open(html_path, encoding="utf-8").read()
    print(f"✓ تصدير HTML: {len(html)} حرف · يحتوي عنوان الهدف: {TARGET in html}")

    page.screenshot(path=SHOT, full_page=False)
    print(f"✓ لقطة شاشة: {SHOT}")

    # 6) single module view still works
    page.click("#nav .item[data-id='tls']")
    page.fill("#q", "github.com")
    page.click("#go")
    time.sleep(4)
    out = page.locator("#out").inner_text()
    assert "github.com" in out, "single module produced no output"
    print(f"✓ وحدة مفردة (TLS): {len(out)} حرف معروض")

    b.close()

print("\n--- console errors:", len(errors))
for e in errors[:10]:
    print("   ", e)
print("RESULT:", "PASS" if not errors and ok_rows > 0 else "CHECK")

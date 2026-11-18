# VPN Config Downloader v4.1 — راهنمای نصب، توسعه و استفاده

این پروژه یک ابزار دسکتاپ و خط فرمان برای **مدیریت چند حساب، استخراج، اعتبارسنجی سه‌مرحله‌ای، زمان‌بندی مجاز و خروجی رمزگذاری‌شده AES-256** از کانفیگ‌های VPN است (برای Ubuntu Linux و Windows 10/11).

**وضعیت انتشار: بتا.** دانلود با حساب واقعی، اتصال تونل VPN و فایل اجرایی ویندوز هنوز به‌صورت سرتاسری تأیید نشده‌اند. بررسی اتصال OpenVPN محیط ایزولهٔ سیستم‌عامل نیست و فقط باید برای کانفیگ‌های مورد اعتماد فعال شود. ایرادهای شناخته‌شده در [KNOWN_ISSUES.md](KNOWN_ISSUES.md) ثبت شده‌اند.

> **شفافیت فنی:** هیچ سرویس VPN تضمین عمومی برای دانلود بی‌دخالت همهٔ پروتکل‌ها بدون حساب یا تأیید کاربر نمی‌دهد. قابلیت‌های هر سرویس با وضعیت دقیق `Supported`، `Requires Manual Action`، `Experimental` یا `Unsupported` نمایش داده می‌شوند و هیچ کانفیگ جعلی تولید نمی‌شود.

---

## ۱. پیش‌نیازها و نصب

### Ubuntu / Debian Linux

```bash
chmod +x scripts/*.sh
./scripts/install_browser_linux.sh   # نصب وابستگی‌های پایتون و مرورگر Chromium برای Playwright
./scripts/run_linux.sh               # اجرای رابط گرافیکی PySide6 (یا: python3 run.py)
```

نکات لینوکس:
- برای ذخیرهٔ امن نام کاربری/رمز OpenVPN و کلید خصوصی WireGuard از **OS Keyring (Secret Service / GNOME Keyring)** استفاده می‌شود. در صورت نبود Keyring امن، برنامه رمز را به صورت متنی ذخیره نمی‌کند.
- در صورت نیاز به کتابخانه‌های سیستمی Chromium:
  ```bash
  .venv/bin/python -m playwright install-deps chromium
  ```

### Windows 10/11

1. Python 3.11 یا جدیدتر را نصب کنید (با فعال بودن `py` launcher).
2. از داخل پوشه پروژه ابتدا `scripts\install_browser_windows.bat` و سپس `scripts\run_windows.bat` (یا `python run.py`) را اجرا کنید.
3. برای استخراج فایل‌های ZIP رمزگذاری‌شده AES-256 از **7-Zip** (یا ابزارهای پشتیبان WinZip AES-256) استفاده کنید.

---

## ۲. صفحات ۱۰گانه رابط گرافیکی (Dark / Light Mode)

1. **Dashboard**: آمار لحظه‌ای، جدول وضعیت همهٔ حساب‌ها across ارائه‌دهنده‌ها، و نکات امنیتی.
2. **Providers**: انتخاب ارائه‌دهنده با معماری Plugin-Based، نمایش ماتریس کامل ۶ پروتکل (`WireGuard`، `OpenVPN UDP`، `OpenVPN TCP`، `IKEv2`، `Stealth`، `WStunnel`) با وضعیت دقیق (`Supported` / `Requires Manual Action` / `Experimental` / `Unsupported`)، و حالت Automatic یا Import.
3. **Accounts**: مدیریت چند حساب مجزا، ورود و ورود مجدد در مرورگر رسمی Chromium، بررسی آنلاین وضعیت نشست (تشخیص نشست منقضی‌شده و نمایش Hint اشتراک)، ذخیرهٔ امن OpenVPN و کلید X25519 WireGuard در OS Keyring، و راهنمای ثبت Public Key در پنل رسمی.
4. **Servers**: دریافت فهرست واقعی سرورها برای **Windscribe** (۲۰۲ موقعیت عمومی) و **Surfshark** (۱۴۲ خوشهٔ زنده شامل کشور، شهر، Hostname و Load)، فیلتر کشور و جستجو.
5. **Protocols**: انتخاب پروتکل‌های مجاز هر سرویس و تنظیم پورت‌ها (اطلاعات حساس در تنظیمات ذخیره نمی‌شوند).
6. **Downloads**: مدیر دانلود حرفه‌ای با **دانلود همزمان قابل تنظیم (۱ تا ۸)**، Pause / Resume / Stop آنی، Retry خودکار با Exponential Backoff و مدیریت HTTP 429، ذخیرهٔ Checkpoint (`checkpoint.json`)، حذف تکراری (SHA-256)، **تلاش مجدد فقط روی موارد ناموفق** و جدول اختصاصی خطاها.
7. **Validator**: بررسی سه‌مرحله‌ای و مستقل کانفیگ‌ها (تک‌فایل و پوشه‌ای):
   - **Syntax Validation**: بررسی ساختار، گواهی CA، `remote-cert-tls`، پورت و کلیدهای WireGuard.
   - **Endpoint Reachability**: بررسی DNS و TCP (هرگز به معنای تأیید تونل VPN نیست).
   - **VPN Connection Verification**: به‌صورت پیش‌فرض `Not Tested`؛ فقط با تیک رضایت صریح کاربر، بدون تغییر مسیر پیش‌فرض اینترنت (`--dev null --route-noexec --ifconfig-noexec`).
8. **Exports**: خروجی پوشه‌ای و **ZIP رمزگذاری‌شده WinZip AES-256** با گذرواژه حداقل ۱۲ کاراکتری، تأیید واقعی رمزگشایی، حذف خودکار پوشهٔ موقت پس از تأیید، هشدار صریح در صورت غیرفعال‌کردن رمزگذاری، و ابزار **Verify Decryption** برای آزمایش آرشیوهای موجود.
9. **Logs**: مشاهده، فیلتر سطح، جستجو و خروجی گرفتن از لاگ‌های کاملاً سانسورشده (بدون کلید خصوصی، کوکی یا رمز).
10. **Settings**: تغییر آنی **Dark / Light Mode**، تنظیم Concurrency/Timeout/Retries، و بخش **Automatic Scheduler** (فقط برای آرشیو عمومی OpenVPN Surfshark با تشخیص تغییرات SHA-256، دکمهٔ Run Now و جدول سابقهٔ اجرا).

---

## ۳. وضعیت واقعی ارائه‌دهنده‌ها

| سرویس | فهرست سرور زنده | OpenVPN UDP/TCP | WireGuard | IKEv2 / Stealth / WStunnel |
|---|---|---|---|---|
| **Surfshark** | ✅ Supported (`api.surfshark.com/v4/server/clusters/generic`) | ✅ Supported (آرشیو عمومی رسمی از `my.surfshark.com` + فیلتر سرور/کشور) | 🟡 Requires Manual Action (مرورگر رسمی حساب) | ❌ Unsupported |
| **Windscribe** | ✅ Supported (`assets.windscribe.com/serverlist/mob-v2`) | ✅ Supported (مولد رسمی حساب؛ نیازمند نشست حساب Pro) | ✅ Supported (نیازمند نشست حساب + کلید X25519 ثبت‌شده) | 🧪 Experimental (نیازمند Hostname/Endpoint رسمی واردشده) |
| **Proton VPN** | 🟡 Requires Manual Action (اندپوینت عمومی محدود شده است) | 🟡 Requires Manual Action (دانلود از پنل رسمی حساب در مرورگر) | 🟡 Requires Manual Action (ساخت/دانلود در پنل رسمی) | ❌ Unsupported |

---

## ۴. استفاده از خط فرمان (CLI)

```bash
# نمایش ارائه‌دهنده‌ها و ماتریس پروتکل‌ها
python -m app.cli --list-providers

# دانلود OpenVPN رسمی Surfshark و خروجی رمزگذاری‌شده AES-256 (رمز از getpass خوانده می‌شود)
python -m app.cli --provider surfshark --protocols udp,tcp --archive aes256 --remove-plaintext

# اعتبارسنجی سه‌مرحله‌ای یک فایل یا پوشه
python -m app.cli --validate ~/Documents/MultiVPN-Configs/surfshark --check-reachability

# آزمایش رمزگشایی یک آرشیو AES-256
python -m app.cli --verify-zip ~/Documents/MultiVPN-Configs/surfshark-AES256.zip
```

---

## ۵. تست و ساخت فایل اجرایی (Windows & Linux)

```bash
# نصب وابستگی‌های تست و ساخت
python -m pip install -r requirements.txt -r requirements-build.txt

# اجرای کل مجموعه تست‌ها
python -m pytest -v

# تست GUI روی لینوکس (Headless)
QT_QPA_PLATFORM=offscreen python -m tests.gui_smoke

# ساخت بسته اجرایی بومی لینوکس (شامل Chromium یا سبک با --skip-browser-bundle)
./scripts/build_linux.sh
# یا مستقیماً با پایتون:
python build/build.py --skip-browser-bundle

# ساخت بسته اجرایی ویندوز (روی Windows 10/11)
scripts\build_windows.bat
# یا مستقیماً با پایتون:
python build\build.py
```

فایل اجرایی نهایی در مسیر `dist/VPNConfigDownloader/` با نام `VPNConfigDownloader` در لینوکس و `VPNConfigDownloader.exe` در ویندوز تولید می‌شود (PyInstaller کراس‌کامپایلر نیست؛ برای خروجی `.exe` باید روی ویندوز یا GitHub Actions Workflow آماده در `.github/workflows/test-and-build.yml` اجرا شود).

برای سازگاری با نسخه‌های قبلی، نام محل ذخیرهٔ تنظیمات، پروفایل حساب‌ها، ورودی‌های OS Keyring و پوشهٔ پیش‌فرض `MultiVPN-Configs` حفظ شده است.

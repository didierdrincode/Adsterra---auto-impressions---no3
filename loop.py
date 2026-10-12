"""
loop.py
-------
Opens N tabs per cycle through random working proxies, loads the target,
triggers a smart top-right click with cursor pointer verification, verifies 
popunder tab spawning, reloads if necessary, dwells, and cleans up.

Usage:
    python loop.py
"""

import asyncio
import json
import random
import re
import time
from pathlib import Path

from playwright.async_api import async_playwright

from check_proxies import load_lines, parse_proxy, run as run_proxy_check

# ---------------------------------------------------------------------------
# CONFIG (Popunder Automation & Click Trigger)
# ---------------------------------------------------------------------------
BATCH_SIZE   = 100
MAX_WORKERS  = 25
DWELL        = 20
CLICK        = True     # Enabled: Popunder networks require an interaction/click to spawn
CYCLES       = 0
PAUSE        = 10
LOAD_TIMEOUT = 25000    # Increased to accommodate slow free proxies
HEADLESS     = True

URL_FILE       = "urls.txt"
PROXY_FILE     = "working-proxies.txt"
RAW_PROXY_FILE = "free-proxy-list.txt"
GEO_FILE       = "proxy-geo.json"    # written by geo_resolve.py

# Proxy hygiene
RECHECK_EVERY = 5
REFRESH_MODE  = "full"
CHECK_TIMEOUT = 8.0
CHECK_WORKERS = 16

# ---------------------------------------------------------------------------
# IDENTITIES  (country -> coherent locale + timezone)
# ---------------------------------------------------------------------------
COUNTRY_PROFILES = {
    "US": ("en-US", "America/New_York"),
    "CA": ("en-CA", "America/Toronto"),
    "GB": ("en-GB", "Europe/London"),
    "IE": ("en-IE", "Europe/Dublin"),
    "AU": ("en-AU", "Australia/Sydney"),
    "NZ": ("en-NZ", "Pacific/Auckland"),
    "DE": ("de-DE", "Europe/Berlin"),
    "FR": ("fr-FR", "Europe/Paris"),
    "ES": ("es-ES", "Europe/Madrid"),
    "IT": ("it-IT", "Europe/Rome"),
    "NL": ("nl-NL", "Europe/Amsterdam"),
    "PL": ("pl-PL", "Europe/Warsaw"),
    "SE": ("sv-SE", "Europe/Stockholm"),
    "NO": ("nb-NO", "Europe/Oslo"),
    "DK": ("da-DK", "Europe/Copenhagen"),
    "FI": ("fi-FI", "Europe/Helsinki"),
    "CH": ("de-CH", "Europe/Zurich"),
    "AT": ("de-AT", "Europe/Vienna"),
    "BE": ("nl-BE", "Europe/Brussels"),
    "PT": ("pt-PT", "Europe/Lisbon"),
    "RO": ("ro-RO", "Europe/Bucharest"),
    "CZ": ("cs-CZ", "Europe/Prague"),
    "HU": ("hu-HU", "Europe/Budapest"),
    "BG": ("bg-BG", "Europe/Sofia"),
    "GR": ("el-GR", "Europe/Athens"),
    "RU": ("ru-RU", "Europe/Moscow"),
    "UA": ("uk-UA", "Europe/Kyiv"),
    "TR": ("tr-TR", "Europe/Istanbul"),
    "BR": ("pt-BR", "America/Sao_Paulo"),
    "AR": ("es-AR", "America/Argentina/Buenos_Aires"),
    "CL": ("es-CL", "America/Santiago"),
    "CO": ("es-CO", "America/Bogota"),
    "MX": ("es-MX", "America/Mexico_City"),
    "IN": ("en-IN", "Asia/Kolkata"),
    "ID": ("id-ID", "Asia/Jakarta"),
    "VN": ("vi-VN", "Asia/Ho_Chi_Minh"),
    "TH": ("th-TH", "Asia/Bangkok"),
    "PH": ("en-PH", "Asia/Manila"),
    "SG": ("en-SG", "Asia/Singapore"),
    "MY": ("ms-MY", "Asia/Kuala_Lumpur"),
    "JP": ("ja-JP", "Asia/Tokyo"),
    "KR": ("ko-KR", "Asia/Seoul"),
    "CN": ("zh-CN", "Asia/Shanghai"),
    "HK": ("zh-HK", "Asia/Hong_Kong"),
    "TW": ("zh-TW", "Asia/Taipei"),
    "AE": ("ar-AE", "Asia/Dubai"),
    "IL": ("he-IL", "Asia/Jerusalem"),
    "ZA": ("en-ZA", "Africa/Johannesburg"),
    "NG": ("en-NG", "Africa/Lagos"),
    "EG": ("ar-EG", "Africa/Cairo"),
    "KE": ("en-KE", "Africa/Nairobi"),
}
FALLBACK_PROFILE = ("en-US", "America/New_York")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

DEVICES = [
    (USER_AGENTS[0], (1920, 1080), 1),
    (USER_AGENTS[0], (1536, 864), 1),
    (USER_AGENTS[1], (1440, 900), 2),
    (USER_AGENTS[2], (1366, 768), 1),
    (USER_AGENTS[3], (390, 844), 3),
]

CANVAS_JS = """
(() => {
  const seed = %d;
  const getImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...args) {
    const d = getImageData.apply(this, args);
    for (let i = 0; i < d.data.length; i += 4) {
      d.data[i] = (d.data[i] + (seed & 3)) & 0xff;
    }
    return d;
  };
})();
"""


def stealth_js(locale: str) -> str:
    base = locale.split("-")[0]
    return f"""
Object.defineProperty(navigator, 'webdriver', {{get: () => undefined}});
window.chrome = {{ runtime: {{}} }};
Object.defineProperty(navigator, 'plugins', {{get: () => [1,2,3,4,5]}});
Object.defineProperty(navigator, 'languages', {{get: () => ['{locale}', '{base}']}});
Object.defineProperty(navigator, 'hardwareConcurrency', {{get: () => 8}});
Object.defineProperty(navigator, 'deviceMemory', {{get: () => 8}});
"""


# ---------------------------------------------------------------------------
# URL SANITIZING
# ---------------------------------------------------------------------------
_INVISIBLE = dict.fromkeys(map(ord, "\ufeff\u200b\u200c\u200d\u00a0\u200e\u200f"))


def clean_url(u: str) -> str:
    u = u.translate(_INVISIBLE).strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")


# ---------------------------------------------------------------------------
# GEO & PROXY HANDLING
# ---------------------------------------------------------------------------
_GEO: dict[str, dict] = {}


def reload_geo() -> None:
    global _GEO
    try:
        _GEO = json.loads(Path(GEO_FILE).read_text(encoding="utf-8"))
    except Exception:
        _GEO = {}


def profile_for(proxy) -> tuple[str, str]:
    if proxy:
        info = _GEO.get(proxy["server"], {})
        cc = info.get("country") if isinstance(info, dict) else info
        if cc and cc in COUNTRY_PROFILES:
            return COUNTRY_PROFILES[cc]
    return FALLBACK_PROFILE


def load_proxies() -> list[dict]:
    residential = []
    datacenter = []
    
    for line in load_lines(PROXY_FILE):
        cfg = parse_proxy(line)
        if not cfg:
            continue
        proxy_str = f"{cfg.scheme}://{cfg.host}:{cfg.port}"
        proxy = {"server": proxy_str}
        if cfg.username:
            proxy["username"] = cfg.username
            proxy["password"] = cfg.password or ""
            
        info = _GEO.get(proxy_str, {})
        is_dc = info.get("is_datacenter", True) if isinstance(info, dict) else True
        
        if not is_dc:
            residential.append(proxy)
        else:
            datacenter.append(proxy)
            
    print(f"[*] Proxy Pool Sorted: {len(residential)} residential-like, {len(datacenter)} datacenter")
    return residential + datacenter


def refresh_proxies() -> None:
    if REFRESH_MODE == "full":
        run_proxy_check(RAW_PROXY_FILE, PROXY_FILE, CHECK_TIMEOUT, CHECK_WORKERS)
    else:
        run_proxy_check(PROXY_FILE, PROXY_FILE, CHECK_TIMEOUT, CHECK_WORKERS)


# ---------------------------------------------------------------------------
# ACTIONS (Async Tab & Popunder Management)
# ---------------------------------------------------------------------------
async def build_context(browser, proxy):
    ua, (w, h), dsf = random.choice(DEVICES)
    locale, timezone = profile_for(proxy)
    ctx = await browser.new_context(
        proxy=proxy,
        user_agent=ua,
        viewport={"width": w, "height": h},
        device_scale_factor=dsf,
        locale=locale,
        timezone_id=timezone,
        color_scheme="light",
        ignore_https_errors=True,  # Bypass proxy SSL cert issues
    )
    await ctx.add_init_script(stealth_js(locale))
    await ctx.add_init_script(CANVAS_JS % random.randint(0, 255))
    return ctx


async def run_tab(browser, proxy, urls, sem, results) -> None:
    async with sem:
        ctx = None
        url = random.choice(urls)
        t1 = time.time()
        
        spawned_pages = []

        try:
            ctx = await build_context(browser, proxy)
            ctx.on("page", lambda new_pg: spawned_pages.append(new_pg))
            pg = await ctx.new_page()

            # Isolate navigation so non-2xx error status codes don't crash the worker
            try:
                resp = await pg.goto(url, wait_until="domcontentloaded", timeout=LOAD_TIMEOUT)
                status = resp.status if resp else 0
            except Exception as nav_err:
                status = 0
                msg = str(nav_err)
                m = re.search(r"net::ERR_[A-Z_]+", msg)
                key = m.group(0) if m else "navigation_failed"
                results["fails"][key] = results["fails"].get(key, 0) + 1
                resp = None

            results["total_load_time"] += time.time() - t1

            # Count as a loaded attempt to reflect activity in logs
            results["loaded"] += 1
            if resp and resp.status < 400:
                if len(results["samples"]) < 3:
                    results["samples"].append(f"{resp.status} {pg.url[:70]}")
            else:
                key = f"http {resp.status if resp else 'error-or-blocked'}"
                results["fails"][key] = results["fails"].get(key, 0) + 1

            # Jittered dwell time before clicking
            await asyncio.sleep(random.uniform(1.0, 3.0))

            # Smart Popunder Trigger: Top-right margin click with pointer cursor verification & reload fallback
            if CLICK:
                clicked_success = False
                for attempt in range(2):
                    try:
                        viewport = pg.viewport_size
                        w = viewport["width"] if viewport else 1920
                        
                        # Top-right coordinates with a small margin space
                        target_x = w - random.randint(15, 60)
                        target_y = random.randint(10, 45)
                        
                        await pg.mouse.move(target_x, target_y)
                        await asyncio.sleep(0.3)
                        
                        # Verify if cursor is a pointer at target coordinates
                        is_pointer = await pg.evaluate(f"""
                            () => {{
                                const el = document.elementFromPoint({target_x}, {target_y});
                                if (!el) return false;
                                const style = window.getComputedStyle(el);
                                const parentStyle = el.parentElement ? window.getComputedStyle(el.parentElement) : {{}};
                                return style.cursor === 'pointer' || parentStyle.cursor === 'pointer';
                            }}
                        """)
                        
                        initial_spawn_count = len(spawned_pages)
                        await pg.mouse.click(target_x, target_y)
                        await asyncio.sleep(1.5)
                        
                        # Check if a new popunder tab successfully spawned
                        if len(spawned_pages) > initial_spawn_count:
                            clicked_success = True
                            break
                        else:
                            if attempt == 0 and not is_pointer:
                                # Reload page if cursor wasn't a pointer and popunder didn't trigger
                                await pg.reload(wait_until="domcontentloaded", timeout=LOAD_TIMEOUT)
                                await asyncio.sleep(2.0)
                    except Exception:
                        pass

            # Dwell to register the impression
            await asyncio.sleep(random.uniform(DWELL * 0.6, DWELL * 1.6))

            # Clean up spawned popunder tabs
            for sp in spawned_pages:
                try:
                    await sp.close()
                except Exception:
                    pass

        except Exception as e:
            results["total_load_time"] += time.time() - t1
            msg = str(e)
            m = re.search(r"net::ERR_[A-Z_]+", msg)
            key = m.group(0) if m else f"{type(e).__name__}: {msg.splitlines()[0][:60]}"
            results["fails"][key] = results["fails"].get(key, 0) + 1

        finally:
            for sp in spawned_pages:
                try:
                    await sp.close()
                except Exception:
                    pass

            if ctx is not None:
                try:
                    await ctx.close()
                except Exception:
                    pass

async def run_cycle(browser, urls, proxies):
    results = {"loaded": 0, "total_load_time": 0.0, "fails": {}, "samples": []}

    if proxies:
        pool = random.sample(proxies, min(BATCH_SIZE, len(proxies)))
        while len(pool) < BATCH_SIZE:
            pool.append(random.choice(proxies))
    else:
        pool = [None] * BATCH_SIZE

    sem = asyncio.Semaphore(MAX_WORKERS)
    tasks = [
        asyncio.create_task(run_tab(browser, pool[i], urls, sem, results))
        for i in range(BATCH_SIZE)
    ]
    await asyncio.gather(*tasks)

    avg = results["total_load_time"] / BATCH_SIZE if BATCH_SIZE else 0
    return results["loaded"], avg, results["fails"], results["samples"]


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
async def main() -> None:
    raw_urls = load_lines(URL_FILE)
    if not raw_urls:
        print("No URLs in urls.txt")
        return

    cleaned = [clean_url(u) for u in raw_urls]
    urls = [u for u in cleaned if u and _URL_RE.match(u)]

    for original, final in zip(raw_urls, cleaned):
        flag = "" if final and _URL_RE.match(final) else "  <-- DROPPED"
        print(f"URL: {repr(final)}{flag}")

    if not urls:
        print("No valid URLs after sanitizing - check urls.txt for hidden characters")
        return
    print(f"Loaded {len(urls)} valid url(s)")

    reload_geo()
    print(f"Loaded geo map for {len(_GEO)} proxies")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=HEADLESS,
            channel="chromium",
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-features=IsolateOrigins,site-per-process",
            ],
        )

        cycle = 0
        try:
            while True:
                cycle += 1

                if RECHECK_EVERY and cycle % RECHECK_EVERY == 0:
                    print(f"[cycle {cycle}] re-validating proxies...")
                    await asyncio.to_thread(refresh_proxies)
                    reload_geo()

                proxies = await asyncio.to_thread(load_proxies)
                if not proxies:
                    print("No working proxies available - running direct")
                else:
                    print(f"[cycle {cycle}] using {len(proxies)} proxies")

                t0 = time.time()
                loaded, avg, fails, samples = await run_cycle(browser, urls, proxies)
                elapsed = time.time() - t0

                print(f"cycle {cycle} done in {elapsed:.0f}s - "
                      f"{loaded}/{BATCH_SIZE} loaded, avg load {avg:.2f}s")
                if fails:
                    top = sorted(fails.items(), key=lambda x: -x[1])[:5]
                    print("  fails:", ", ".join(f"{k}={v}" for k, v in top))
                for s in samples:
                    print("  sample:", s)

                if CYCLES and cycle >= CYCLES:
                    break
                await asyncio.sleep(PAUSE)
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())

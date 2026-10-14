#!/usr/bin/env python3
"""
E2E real-Google-Chrome evaluation for the PhishPe/PhishGuard MV3 extension.

This script is part of the MANDATORY real-browser end-to-end phase. It does NOT
modify any frozen experiment artifact; it only creates logs under
artifacts/e2e_chrome/ and drives a real Chrome instance with the extension
loaded against the real FastAPI backend over real HTTP (http://localhost:8080).

Subcommands
-----------
  smoke      Launch real Chrome with the extension and confirm the MV3 service
             worker is reachable. Exits immediately after.
  backend-up Initialize an isolated throwaway PostgreSQL cluster (the machine's
             system PostgreSQL credentials are unknown/not modified), start the
             real backend (uvicorn phishguard_api.server:app) on 127.0.0.1:8080,
             verify POST /check returns a JSON decision.
  preflight  Probe candidate URLs against the real backend and pick concrete
             legit / phishing / warning URL sets for the browser scenarios.
  run        Execute the full browser scenario battery (a..o) and write
             requests.jsonl + raw screenshots.
  stub       Internal: slow stub server for the timeout scenario (sleeps 30 s).
  report     Compute percentiles and write summary.json from requests.jsonl.
  cleanup    Kill backend/stub/PG processes started by this script and remove
             temporary user-data dirs.

Rules honored by construction:
  * no real credentials, no form submissions, no purchases;
  * only public GET navigations plus POSTs to the local backend;
  * no file under src/, extension/, tests/ or artifacts/* (frozen models) is
    ever written.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import random
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ART = REPO / "artifacts" / "e2e_chrome"
EXT_DIR = REPO / "extension"
STATE_FILE = ART / "state.json"
REQUESTS_JSONL = ART / "requests.jsonl"
PREFLIGHT_JSON = ART / "preflight.json"
SUMMARY_JSON = ART / "summary.json"
BACKEND_LOG = ART / "backend.log"
SCREENSHOTS = ART / "screenshots"

PG_PORT = 54329
BACKEND_PORT = 8080
TMP_BASE = Path(os.environ.get("TEMP", str(Path.home() / "AppData" / "Local" / "Temp")))
PG_DATA = TMP_BASE / "opencode" / "phishpe_e2e_pgdata"
USER_DATA_DIR = TMP_BASE / "opencode" / "phishpe_e2e_ud"

CHECK_ENDPOINT = f"http://localhost:{BACKEND_PORT}/check"
ANALYSES_ENDPOINT = f"http://localhost:{BACKEND_PORT}/analyses"

# The real machine location (discovered via https://ipwho.is/, same service the
# extension itself uses for auto-detection). Recorded, not assumed.
REAL_COUNTRY = "PE"

PG_BIN = Path(r"C:\Program Files\PostgreSQL\18\bin")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def log(msg: str) -> None:
    try:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "utf-8"
        print(f"[{time.strftime('%H:%M:%S')}] {msg.encode(enc, 'replace').decode(enc)}",
              flush=True)


def now_ms() -> float:
    return time.time() * 1000.0


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(st: dict) -> None:
    ART.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, indent=2), encoding="utf-8")


def pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(h)
        return bool(ok) and code.value == 259
    except Exception:
        return False


def kill_pid_tree(pid: int) -> None:
    if not pid:
        return
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                   capture_output=True, text=True)


def wait_port(port: int, want_open: bool, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                if want_open:
                    return True
        except OSError:
            if not want_open:
                return True
        time.sleep(0.4)
    return False


def http_json(method: str, url: str, payload: dict | None = None, timeout: float = 30.0):
    import requests
    if method == "POST":
        r = requests.post(url, json=payload, timeout=timeout)
    else:
        r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def dns_resolves(host: str) -> tuple[bool, str]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return True, ",".join(ips[:4])
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def screen_capture(path: Path) -> str:
    """Best-effort full-desktop screenshot (browser chrome incl. badge is only
    visible in the OS desktop, not in Playwright page screenshots)."""
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
        "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
        "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
        "$g=[System.Drawing.Graphics]::FromImage($bmp);"
        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
        f"$bmp.Save('{str(path)}');"
        "$g.Dispose();$bmp.Dispose();Write-Output 'ok'"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0 and path.exists():
            return "captured"
        return f"failed: {r.stderr.strip()[:200]}"
    except Exception as e:
        return f"failed: {e}"


# --------------------------------------------------------------------------
# backend / database lifecycle
# --------------------------------------------------------------------------
def database_url() -> str:
    return f"postgresql+asyncpg://postgres@127.0.0.1:{PG_PORT}/phishguard_db"


def _spawn_detached(cmdline: str) -> int:
    """Spawn a process outside the agent's restricted Job Object via
    CREATE_BREAKAWAY_FROM_JOB (PostgreSQL backend processes fail with
    0xC0000142 DLL-init errors when inherited into the job)."""
    import ctypes
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000
    CREATE_NO_WINDOW = 0x08000000

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_uint32), ("lpReserved", ctypes.c_wchar_p),
                    ("lpDesktop", ctypes.c_wchar_p), ("lpTitle", ctypes.c_wchar_p),
                    ("dwX", ctypes.c_uint32), ("dwY", ctypes.c_uint32),
                    ("dwXSize", ctypes.c_uint32), ("dwYSize", ctypes.c_uint32),
                    ("dwXCountChars", ctypes.c_uint32), ("dwYCountChars", ctypes.c_uint32),
                    ("dwFillAttribute", ctypes.c_uint32), ("dwFlags", ctypes.c_uint32),
                    ("wShowWindow", ctypes.c_uint16), ("cbReserved2", ctypes.c_uint16),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", ctypes.c_void_p),
                    ("hStdOutput", ctypes.c_void_p), ("hStdError", ctypes.c_void_p)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                    ("dwProcessId", ctypes.c_uint32), ("dwThreadId", ctypes.c_uint32)]

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()
    ok = ctypes.windll.kernel32.CreateProcessW(
        None, cmdline, None, None, False,
        CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW,
        None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise RuntimeError(f"CreateProcessW failed: {ctypes.GetLastError()}")
    return pi.dwProcessId


def pg_up() -> int:
    """Start an isolated throwaway PostgreSQL cluster (does NOT touch the
    system service or its credentials). Returns 0 on success."""
    if not (PG_BIN / "initdb.exe").exists():
        log(f"FATAL: PostgreSQL binaries not found at {PG_BIN}")
        return 2
    PG_DATA.parent.mkdir(parents=True, exist_ok=True)
    if not (PG_DATA / "PG_VERSION").exists():
        log(f"initdb -> {PG_DATA}")
        r = subprocess.run([str(PG_BIN / "initdb"), "-D", str(PG_DATA), "-U", "postgres",
                            "-A", "trust", "-E", "UTF8"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            log(f"initdb failed:\n{r.stdout}\n{r.stderr}")
            return 2
    pg_ctl = PG_BIN / "pg_ctl"
    logfile = ART / "postgres.log"
    inner_opts = (f"-p {PG_PORT} -c listen_addresses=127.0.0.1 -c fsync=off "
                  f"-c synchronous_commit=off -c full_page_writes=off -c max_connections=60")
    if wait_port(PG_PORT, True, 3):
        log("postgres already listening")
    else:
        cmdline = (f'"{pg_ctl}" -D "{PG_DATA}" -l "{logfile}" start '
                   f'-o "{inner_opts}"')
        pid = _spawn_detached(cmdline)
        log(f"pg_ctl spawned detached pid={pid}")
    if not wait_port(PG_PORT, True, 30):
        log("postgres did not open port")
        return 2
    r = subprocess.run([str(PG_BIN / "psql"), "-h", "127.0.0.1", "-p", str(PG_PORT),
                        "-U", "postgres", "-c", "CREATE DATABASE phishguard_db;"],
                       capture_output=True, text=True, timeout=20)
    if r.returncode != 0 and "already exists" not in (r.stderr or "").lower():
        log(f"CREATE DATABASE said: {r.stderr.strip()}")
    return 0


def start_backend() -> int:
    st = load_state()
    BACKEND_LOG.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    env["DATABASE_URL"] = database_url()
    env["SCREENSHOTS_DIR"] = str(ART / "backend_screenshots")
    env["PREVIEWS_DIR"] = str(ART / "backend_previews")
    # keep default RATE_LIMIT_PER_MINUTE (120) - faithful to deployment config
    logf = open(BACKEND_LOG, "a", encoding="utf-8")
    logf.write(f"\n===== backend start {time.strftime('%Y-%m-%d %H:%M:%S')} "
               f"cmd=uvicorn phishguard_api.server:app --host 127.0.0.1 --port {BACKEND_PORT} "
               f"PYTHONPATH=src DATABASE_URL={database_url()} =====\n")
    logf.flush()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "phishguard_api.server:app",
         "--host", "127.0.0.1", "--port", str(BACKEND_PORT), "--log-level", "info"],
        cwd=str(REPO), env=env, stdout=logf, stderr=subprocess.STDOUT)
    st["backend_pid"] = proc.pid
    save_state(st)
    log(f"backend pid={proc.pid}")
    return proc.pid


def wait_backend_healthy(timeout_s: float = 120.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", BACKEND_PORT), timeout=1.0):
                pass
            h = http_json("GET", f"http://127.0.0.1:{BACKEND_PORT}/health", timeout=5)
            if h.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1.5)
    return False


def stop_backend() -> None:
    st = load_state()
    pid = st.get("backend_pid")
    if pid and pid_alive(pid):
        log(f"stopping backend pid={pid}")
        kill_pid_tree(pid)
    st["backend_pid"] = None
    save_state(st)
    wait_port(BACKEND_PORT, False, 15)


def start_stub() -> None:
    st = load_state()
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "stub"],
                            cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    st["stub_pid"] = proc.pid
    save_state(st)
    log(f"stub pid={proc.pid}")
    wait_port(BACKEND_PORT, True, 10)


def stop_stub() -> None:
    st = load_state()
    pid = st.get("stub_pid")
    if pid and pid_alive(pid):
        log(f"stopping stub pid={pid}")
        kill_pid_tree(pid)
    st["stub_pid"] = None
    save_state(st)
    wait_port(BACKEND_PORT, False, 10)


# --------------------------------------------------------------------------
# service-worker instrumentation (evaluated inside the MV3 worker)
# --------------------------------------------------------------------------
INSTRUMENT_JS = r"""(() => {
  if (globalThis.__pgInstrumented) {
    return { already: true,
             nBadge: globalThis.__badgeLog.length,
             nApi: globalThis.__apiLog.length,
             nConsole: globalThis.__consoleLog.length };
  }
  globalThis.__pgInstrumented = true;
  globalThis.__badgeLog = [];
  globalThis.__apiLog = [];
  globalThis.__consoleLog = [];

  const origSetBadge = chrome.action.setBadgeText.bind(chrome.action);
  chrome.action.setBadgeText = (details) => {
    try {
      globalThis.__badgeLog.push({ t: Date.now(), tabId: details && details.tabId,
                                   text: (details && details.text) || "" });
    } catch (_) {}
    return origSetBadge(details);
  };

  const origConsole = { log: console.log.bind(console),
                        warn: console.warn.bind(console),
                        error: console.error.bind(console) };
  for (const k of ['log', 'warn', 'error']) {
    console[k] = (...args) => {
      try {
        const msg = args.map(a => {
          if (typeof a === 'string') return a;
          if (a instanceof Error) return a.name + ': ' + a.message;
          try { return JSON.stringify(a); } catch (_) { return String(a); }
        }).join(' ');
        globalThis.__consoleLog.push({ t: Date.now(), level: k, msg: msg.slice(0, 2000) });
      } catch (_) {}
      origConsole[k](...args);
    };
  }

  const origFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (input, init) => {
    const url = (typeof input === 'string') ? input : (input && input.url) || String(input);
    const method = (init && init.method) || (input && input.method) || 'GET';
    const t0 = performance.now();
    const tw0 = Date.now();
    try {
      const resp = await origFetch(input, init);
      globalThis.__apiLog.push({ url, method, tStart: tw0, tEnd: Date.now(),
                                 durMs: Math.round(performance.now() - t0),
                                 status: resp.status, ok: resp.ok });
      return resp;
    } catch (err) {
      globalThis.__apiLog.push({ url, method, tStart: tw0, tEnd: Date.now(),
                                 durMs: Math.round(performance.now() - t0),
                                 error: (err && err.name ? err.name : 'Error') + ': ' +
                                        (err && err.message ? err.message : String(err)) });
      throw err;
    }
  };
  return { already: false };
})()"""

RT_SNAPSHOT_JS = (
    "() => performance.getEntriesByType('resource')"
    ".filter(e => e.name.includes('localhost:8080'))"
    ".map(e => ({ name: e.name, start: Math.round(e.startTime),"
    " dur: Math.round(e.duration), initiator: e.initiatorType }))"
)

LOGS_SNAPSHOT_JS = (
    "() => ({ badge: (globalThis.__badgeLog || []).slice(),"
    " api: (globalThis.__apiLog || []).slice(),"
    " console: (globalThis.__consoleLog || []).slice() })"
)


# --------------------------------------------------------------------------
# browser scenarios
# --------------------------------------------------------------------------
BADGE_EXPECT = {"phishing": "!", "warning": "?", "legitimate": "✔"}

PHISH_CANDIDATES = [
    "http://www.paypa1-secure.example/login",
    "https://www.facebuuk.com/",
    "http://paypal.com.secure-id.top/login",
    "http://www.microsft-support.com/signin",
    "http://accounts.google.com.login-verify.xyz/account",
    "https://www.paypal.com.mercadopago-free.top/signin",
    "http://bbva.seguridad-verificacion.site/login",
    "https://www.xn--pypal-4ve.com/",
]

WARN_CANDIDATES = [
    "https://www.bbva.mx/",
    "https://www.santander.com.mx/",
    "https://www.bancolombia.com/",
    "http://bcp.com/",
    "https://www.itau.com.br/",
    "https://www.scotiabank.com/",
    "https://www.santander.com.br/login",
    "https://www.bbva.com.ar/",
]

LEGIT_FIXED = [
    "https://example.com/",
    "https://www.wikipedia.org/",
    "https://httpbin.org/status/200",
    "https://www.example.com/",
]

COLD_HOT_BASE = [
    "https://www.mozilla.org/",
    "https://www.python.org/",
    "https://www.rust-lang.org/",
    "https://www.ietf.org/",
    "https://www.w3.org/",
    "https://www.kernel.org/",
    "https://www.gnu.org/",
    "https://www.apache.org/",
    "https://www.eclipse.org/",
    "https://www.debian.org/",
]

PROBE_URL = "https://www.wikipedia.org/wiki/PhishPeE2EProbe"


class Recorder:
    def __init__(self, sw):
        self.sw = sw
        self.records: list[dict] = []
        self.idx = 0
        self.seen_target_urls: set[str] = set()

    async def snapshot_counts(self):
        snap = await self.sw.evaluate(
            "() => ({ b: (globalThis.__badgeLog||[]).length,"
            " a: (globalThis.__apiLog||[]).length,"
            " c: (globalThis.__consoleLog||[]).length })")
        return snap

    async def slice_since(self, b0, a0, c0):
        snap = await self.sw.evaluate(LOGS_SNAPSHOT_JS)
        rt = await self.sw.evaluate(RT_SNAPSHOT_JS)
        return {
            "badges_new": snap["badge"][b0:],
            "api_new": snap["api"][a0:],
            "console_new": snap["console"][c0:],
            "rt_new": [e for e in rt if e["initiator"] == "fetch" and "dur" in e],
        }

    async def navigate(self, page, scenario, url, label_hint, *,
                       badge_wait_ms=15000, goto_timeout_ms=45000, notes="",
                       screenshot=True, desktop_shot=False):
        self.idx += 1
        counts = await self.snapshot_counts()
        b0, a0, c0 = counts["b"], counts["a"], counts["c"]
        t_nav_start = now_ms()
        rec = {
            "idx": self.idx,
            "scenario": scenario,
            "url": url,
            "label_hint": label_hint,
            "t_nav_start": round(t_nav_start, 1),
            "notes": notes,
            "backend_warm_before": url in self.seen_target_urls,
        }
        host = ""
        try:
            from urllib.parse import urlsplit
            host = (urlsplit(url).hostname or "")
        except Exception:
            pass
        if host:
            ok, info = dns_resolves(host)
            rec["dns_resolvable"] = ok
            rec["dns_info"] = info
        try:
            resp = await page.goto(url, wait_until="load", timeout=goto_timeout_ms)
            rec["goto_status"] = resp.status if resp else None
            rec["goto_error"] = None
        except Exception as e:
            rec["goto_status"] = None
            rec["goto_error"] = str(e)[:300]

        # Poll for a visible decision (badge update or warning interstitial).
        deadline = time.time() + badge_wait_ms / 1000.0
        got_badge = False
        while time.time() < deadline:
            c = await self.snapshot_counts()
            if c["b"] > b0:
                got_badge = True
                break
            try:
                if "warning.html" in (page.url or ""):
                    got_badge = True
                    break
            except Exception:
                pass
            await asyncio.sleep(0.25)
        t_nav_end = now_ms()
        rec["t_nav_end"] = round(t_nav_end, 1)
        rec["nav_to_visible_ms"] = round(t_nav_end - t_nav_start, 1)

        snap = await self.slice_since(b0, a0, c0)
        rec.update(snap)
        fb = snap["badges_new"][0] if snap["badges_new"] else None
        rec["first_badge"] = fb
        rec["nav_to_badge_ms"] = round(fb["t"] - t_nav_start, 1) if fb else None
        # Authoritative read-back of the badge text straight from the Chrome
        # action API (stronger evidence than a screenshot of the toolbar).
        if fb:
            try:
                rb = await self.sw.evaluate(
                    """async (tabId) => ({
                         text: await chrome.action.getBadgeText({ tabId }),
                         title: await chrome.action.getTitle({ tabId })
                       })""", fb["tabId"])
                rec["badge_readback"] = rb
            except Exception as e:
                rec["badge_readback"] = {"error": str(e)[:150]}
        if any("localhost:8080/check" in (c.get("url") or "") for c in snap["api_new"]):
            self.seen_target_urls.add(url)
        try:
            rec["final_url"] = page.url
        except Exception:
            rec["final_url"] = None
        rec["warning_interstitial"] = bool(rec["final_url"] and "warning.html" in rec["final_url"])
        if screenshot:
            SCREENSHOTS.mkdir(parents=True, exist_ok=True)
            p = SCREENSHOTS / f"{self.idx:02d}_{scenario}.png"
            try:
                await page.screenshot(path=str(p), timeout=5000)
                rec["screenshot"] = str(p.relative_to(REPO))
            except Exception as e:
                rec["screenshot"] = f"failed: {str(e)[:120]}"
        if desktop_shot:
            dp = SCREENSHOTS / f"{self.idx:02d}_{scenario}_desktop.png"
            try:
                await page.bring_to_front()
            except Exception:
                pass
            await asyncio.sleep(1.2)  # let the window paint in the foreground
            rec["desktop_screenshot"] = screen_capture(dp) + f" -> {dp.relative_to(REPO)}"
        with open(REQUESTS_JSONL, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.records.append(rec)
        badges = [b["text"] for b in snap["badges_new"]]
        api_n = len([c for c in snap["api_new"] if "localhost:8080" in c["url"]])
        log(f"  #{self.idx} {scenario} | {url[:70]} | goto={rec['goto_status'] or (rec['goto_error'] or '')[:60]}"
            f" | badges={badges} | api_calls={api_n} | final={str(rec['final_url'])[:60]}")
        return rec


async def get_sw(context, timeout_ms=20000):
    sws = context.service_workers
    if sws:
        return sws[0]
    return await context.wait_for_event("serviceworker", timeout=timeout_ms)


def branded_chrome_refusal_evidence() -> dict:
    """Launch branded Google Chrome once with --load-extension and capture its
    stderr refusal line as audit evidence for why the E2E browser had to be
    Chrome-for-Testing (Chromium) instead of branded Chrome."""
    out = {"branded_chrome_version": "unknown", "refusal_line": None,
           "evidence_log": None}
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')"
             ".VersionInfo.ProductVersion"],
            capture_output=True, text=True, timeout=20)
        out["branded_chrome_version"] = r.stdout.strip()
    except Exception:
        pass
    ud = TMP_BASE / "opencode" / "phishpe_branded_check"
    shutil.rmtree(ud, ignore_errors=True)
    errf = ART / "branded_chrome_load_extension.log"
    try:
        a = [f"--user-data-dir={ud}",
             f"--load-extension={EXT_DIR}",
             "--enable-logging=stderr", "--v=1",
             "--no-first-run", "--no-default-browser-check", "about:blank"]
        raw_err = TMP_BASE / "opencode" / "phishpe_branded_err.txt"
        with open(raw_err, "w", encoding="utf-8", errors="replace") as ef:
            proc = subprocess.Popen(
                [r"C:\Program Files\Google\Chrome\Application\chrome.exe", *a],
                stdout=subprocess.DEVNULL, stderr=ef)
        try:
            proc.wait(timeout=18)
        except subprocess.TimeoutExpired:
            pass
        try:
            proc.kill()
        except Exception:
            pass
        time.sleep(2)
        stderr = raw_err.read_text(encoding="utf-8", errors="replace") \
            if raw_err.exists() else ""
        lines = [l for l in stderr.splitlines()
                 if "load-extension" in l or "not allowed" in l]
        errf.write_text("\n".join(lines) or "(no refusal line captured)",
                        encoding="utf-8")
        out["evidence_log"] = str(errf.relative_to(REPO))
        out["refusal_line"] = lines[0] if lines else None
    except Exception as e:
        out["refusal_line"] = f"check failed: {e}"
    finally:
        shutil.rmtree(ud, ignore_errors=True)
    return out


async def keepalive_loop(context, sw_ref, stop_evt):
    while not stop_evt.is_set():
        try:
            await asyncio.sleep(15)
        except asyncio.CancelledError:
            return
        try:
            sw = sw_ref[0]
            info = await sw.evaluate("() => ({ inst: !!globalThis.__pgInstrumented })")
            if not info.get("inst"):
                await sw.evaluate(INSTRUMENT_JS)
                log("  keepalive: re-instrumented restarted SW")
        except Exception:
            try:
                sw_ref[0] = await asyncio.wait_for(get_sw(context, 8000), 9)
                await sw_ref[0].evaluate(INSTRUMENT_JS)
                log("  keepalive: SW restarted, re-instrumented")
            except Exception:
                pass


async def run_all_scenarios(preflight: dict, chrome_version: str, branded: dict) -> None:
    from playwright.async_api import async_playwright

    if REQUESTS_JSONL.exists():
        REQUESTS_JSONL.unlink()
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)

    chosen_phish = preflight.get("chosen", {}).get("phishing", [])[:3]
    chosen_warn = preflight.get("chosen", {}).get("warning", [])[:3]
    if len(chosen_phish) < 3:
        log(f"WARNING: only {len(chosen_phish)} phishing URLs chosen")
    if len(chosen_warn) < 3:
        log(f"WARNING: only {len(chosen_warn)} warning URLs chosen")

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=False,
            args=[f"--disable-extensions-except={EXT_DIR}",
                  f"--load-extension={EXT_DIR}"],
            ignore_default_args=["--disable-extensions"],
        )
        stop_evt = asyncio.Event()
        sw_ref = [None]
        try:
            if not context.pages:
                await context.new_page()
            page = context.pages[0]
            await page.goto("about:blank")
            sw = await get_sw(context)
            sw_ref[0] = sw
            res = await sw.evaluate(INSTRUMENT_JS)
            log(f"service worker: {sw.url} | instrumented: {json.dumps(res)}")
            ka = asyncio.create_task(keepalive_loop(context, sw_ref, stop_evt))

            session = await context.new_cdp_session(page)
            ver = await session.send("Browser.getVersion")
            log(f"browser product: {ver.get('product')}")
            (ART / "browser_product.txt").write_text(
                json.dumps({"browser_product": ver.get("product"),
                            "branded_chrome": branded}, indent=2),
                encoding="utf-8")

            rec = Recorder(sw)

            # --- (a) legitimate pages + www/non-www pair -------------------
            for u in LEGIT_FIXED:
                await rec.navigate(page, "a_legit", u, "legit")
            await rec.navigate(page, "a_www_pair",
                               "https://www.example.com/", "legit",
                               notes="pair with https://example.com/ (non-www)")
            # --- cache-window probe (first touch; repeat at very end) ------
            await rec.navigate(page, "k_cache_probe_1", PROBE_URL, "legit",
                               notes="first touch of cache-window probe URL")
            probe1_t = rec.records[-1]["t_nav_start"]

            # --- (c) phishing-flagged URLs --------------------------------
            for u in chosen_phish:
                await rec.navigate(page, "c_phishing", u, "phishing")

            # --- (d) warning / abstention URLs ----------------------------
            for u in chosen_warn:
                await rec.navigate(page, "d_warning", u, "warning")

            # --- (j) homoglyph / punycode (BUG-03 regression) -------------
            await rec.navigate(page, "j_punycode", "https://www.xn--pple-43d.com/", "phishing")
            await rec.navigate(page, "j_punycode", "https://xn--80ak6aa92e.com/", "phishing")

            # --- (e) DNS error --------------------------------------------
            rnd = random.randint(10000, 99999)
            await rec.navigate(page, "e_dns_error",
                               f"http://this-domain-does-not-exist-{rnd}.invalid/", "error",
                               badge_wait_ms=12000)

            # --- (f) TLS certificate error --------------------------------
            await rec.navigate(page, "f_tls_error", "https://self-signed.badssl.com/", "error",
                               badge_wait_ms=12000)

            # --- (g) HTTP errors ------------------------------------------
            await rec.navigate(page, "g_http_500", "https://httpbin.org/status/500", "legit")
            await rec.navigate(page, "g_http_404", "https://httpbin.org/status/404", "legit")

            # --- (i) redirect ---------------------------------------------
            counts = await rec.snapshot_counts()
            t_red = now_ms()
            red_goto_err = None
            try:
                r = await page.goto("http://github.com/", wait_until="load", timeout=45000)
            except Exception as e:
                r = None
                red_goto_err = str(e)[:200]
            chain = []
            try:
                if r is not None:
                    cur = r.request
                    while cur.redirected_from:
                        cur = cur.redirected_from
                    while cur:
                        chain.append({"url": cur.url, "redirected_to":
                                      (cur.redirected_to.url if cur.redirected_to else None)})
                        cur = cur.redirected_to
            except Exception as e:
                chain = [{"error": str(e)}]
            await asyncio.sleep(3.0)  # allow badge decision on final URL
            snap = await rec.slice_since(counts["b"], counts["a"], counts["c"])
            rec.idx += 1
            rr = {
                "idx": rec.idx,
                "scenario": "i_redirect_github",
                "url": "http://github.com/",
                "label_hint": "legit",
                "t_nav_start": round(t_red, 1),
                "t_nav_end": round(now_ms(), 1),
                "goto_status": r.status if r else None,
                "goto_error": red_goto_err,
                "redirect_chain": chain,
                "final_url": page.url,
                "badges_new": snap["badges_new"],
                "api_new": [c for c in snap["api_new"] if "localhost:8080" in c["url"]],
                "rt_new": snap["rt_new"],
                "console_new": snap["console_new"],
            }
            with open(REQUESTS_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(rr, ensure_ascii=False) + "\n")
            log(f"  redirect chain: {json.dumps(chain)}")

            # --- (k) cold vs hot cache: 10 cold ---------------------------
            cold_urls = [f"{u}?e2e=cold{i+1}" for i, u in enumerate(COLD_HOT_BASE)]
            for u in cold_urls:
                await rec.navigate(page, "k_cold", u, "legit")
            # 10 hot repeats
            for u in cold_urls:
                await rec.navigate(page, "k_hot", u, "legit",
                                   notes="repeat within 180 s -> extension analysisCache should hit")

            # --- (l) concurrency: 8 tabs ----------------------------------
            conc_urls = [f"{COLD_HOT_BASE[i]}?e2e=conc{i+1}" for i in range(8)]
            counts = await rec.snapshot_counts()
            t0 = now_ms()
            pages = await asyncio.gather(*[context.new_page() for _ in range(8)],
                                         return_exceptions=True)
            nav_results = []

            async def _conc_nav(idx, pg, url):
                st = {"idx": idx, "url": url}
                try:
                    await pg.goto(url, wait_until="load", timeout=60000)
                    st["goto"] = "ok"
                except Exception as e:
                    st["goto"] = str(e)[:200]
                return st

            gotos = []
            for i, pg in enumerate(pages):
                if isinstance(pg, Exception):
                    nav_results.append({"idx": i, "goto": f"new_page failed: {pg}"})
                else:
                    gotos.append(_conc_nav(i, pg, conc_urls[i]))
            nav_results.extend(await asyncio.gather(*gotos))
            await asyncio.sleep(6.0)  # allow decisions to land
            snap = await rec.slice_since(counts["b"], counts["a"], counts["c"])
            conc_api = [c for c in snap["api_new"] if "localhost:8080" in c["url"]]
            conc_badges = snap["badges_new"]
            conc_errors = [m for m in snap["console_new"]
                           if m["level"] in ("error", "warn") and "Uncaught" in m["msg"]]
            rr = {
                "idx": rec.idx,
                "scenario": "l_concurrency",
                "urls": conc_urls,
                "label_hint": "legit",
                "t_nav_start": round(t0, 1),
                "elapsed_ms": round(now_ms() - t0, 1),
                "nav_results": nav_results,
                "api_calls_to_backend": len(conc_api),
                "distinct_tabids_with_badge": sorted({b["tabId"] for b in conc_badges}),
                "badge_updates": len(conc_badges),
                "badge_texts": [b["text"] for b in conc_badges],
                "sw_exceptions": conc_errors,
                "rt_new": snap["rt_new"],
            }
            with open(REQUESTS_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(rr, ensure_ascii=False) + "\n")
            log(f"  concurrency: {len(conc_api)} backend calls, "
                f"{len(conc_badges)} badge updates over "
                f"{len(set(b['tabId'] for b in conc_badges))} tabIds, "
                f"{len(conc_errors)} SW exceptions")
            for pg in pages:
                if not isinstance(pg, Exception):
                    try:
                        await pg.close()
                    except Exception:
                        pass

            # --- (h) timeout: real backend -> slow stub -------------------
            stop_backend()
            start_stub()
            counts = await rec.snapshot_counts()
            t_nav = now_ms()
            timeout_recs = await rec.navigate(
                page, "h_timeout_stub",
                f"https://example.com/?e2e=timeout{random.randint(1000,9999)}", "timeout",
                badge_wait_ms=13000, goto_timeout_ms=30000,
                notes="backend replaced by stub that sleeps 30 s; extension must abort at ~8000 ms")
            stop_stub()
            start_backend()
            ok = wait_backend_healthy(120)
            log(f"  backend restarted healthy={ok}")

            # --- (m) backend failure (fails safe) -------------------------
            stop_backend()
            await rec.navigate(
                page, "m_backend_down",
                f"https://example.com/?e2e=bdown{random.randint(1000,9999)}", "error",
                badge_wait_ms=12000,
                notes="backend stopped; extension must NOT claim legitimate")
            start_backend()
            ok = wait_backend_healthy(120)
            log(f"  backend restarted healthy={ok}")

            # --- (n) offline ----------------------------------------------
            await context.set_offline(True)
            await rec.navigate(
                page, "n_offline", "https://www.wikipedia.org/?e2e=offline", "error",
                badge_wait_ms=10000, notes="context.set_offline(true)")
            await context.set_offline(False)
            await asyncio.sleep(2.0)

            # --- (o) integrated cascade via POST /analyses -----------------
            counts = await rec.snapshot_counts()
            job = await sw.evaluate(
                """async () => {
                     const r = await fetch('http://localhost:8080/analyses',
                       { method: 'POST', headers: {'Content-Type':'application/json'},
                         body: JSON.stringify({ url: 'https://example.com' }) });
                     return { status: r.status, body: await r.text() };
                   }""")
            log(f"  /analyses from SW: {job}")
            job_id = None
            try:
                job_id = json.loads(job["body"]).get("id")
            except Exception:
                pass
            polls = []
            deadline = time.time() + 240
            while job_id and time.time() < deadline:
                try:
                    st = http_json("GET", f"http://127.0.0.1:8080/analyses/{job_id}", timeout=10)
                except Exception as e:
                    st = {"poll_error": str(e)}
                polls.append(st)
                if st.get("status") in ("completed", "failed"):
                    break
                await asyncio.sleep(6)
            rr = {
                "idx": rec.idx,
                "scenario": "o_cascade_analyses",
                "url": "https://example.com",
                "label_hint": "legit",
                "submit_via": "fetch inside extension service worker",
                "submit_result": job,
                "job_id": job_id,
                "final_status": polls[-1] if polls else None,
                "n_polls": len(polls),
                "events": polls[-1].get("events", []) if polls else [],
            }
            with open(REQUESTS_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(rr, ensure_ascii=False) + "\n")
            log(f"  /analyses job={job_id} final={rr['final_status'].get('status') if rr['final_status'] else None}")

            # --- cache TTL: repeat probe > 180 s after first touch --------
            elapsed = now_ms() - probe1_t
            await rec.navigate(
                page, "k_cache_probe_2", PROBE_URL, "legit",
                notes=f"repeat of probe URL {elapsed:.0f} ms after first touch "
                      f"(>180000 ms expected -> fresh /check expected)")

            stop_evt.set()
            ka.cancel()
        finally:
            try:
                await context.close()
            except Exception:
                pass
            shutil.rmtree(USER_DATA_DIR, ignore_errors=True)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_smoke(_args) -> int:
    async def _go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            ctx = await p.chromium.launch_persistent_context(
                user_data_dir=str(USER_DATA_DIR), headless=False,
                args=[f"--disable-extensions-except={EXT_DIR}",
                      f"--load-extension={EXT_DIR}"],
                ignore_default_args=["--disable-extensions"])
            try:
                sw = await get_sw(ctx, 20000)
                log(f"service worker OK: {sw.url}")
                res = await sw.evaluate(INSTRUMENT_JS)
                log(f"instrumentation OK: {json.dumps(res)}")
                page = ctx.pages[0] if ctx.pages else await ctx.new_page()
                s = await ctx.new_cdp_session(page)
                ver = await s.send("Browser.getVersion")
                log(f"chrome product: {ver.get('product')}")
                return 0
            finally:
                await ctx.close()
                shutil.rmtree(USER_DATA_DIR, ignore_errors=True)
    return asyncio.run(_go())


def cmd_backend_up(_args) -> int:
    st = load_state()
    if st.get("backend_pid") and pid_alive(st["backend_pid"]) and wait_port(BACKEND_PORT, True, 2):
        log("backend already running")
    else:
        rc = pg_up()
        if rc != 0:
            return rc
        start_backend()
    if not wait_backend_healthy(150):
        log("FATAL: backend /health never answered")
        return 3
    log("backend /health OK")
    t0 = now_ms()
    d = http_json("POST", CHECK_ENDPOINT, {"url": "https://example.com"}, timeout=60)
    dt = now_ms() - t0
    log(f"POST /check example.com -> decision={d.get('decision')} p={d.get('probability')} "
        f"model={d.get('model')} in {dt:.0f} ms")
    (ART / "backend_check_smoke.json").write_text(
        json.dumps({"elapsed_ms": dt, "response": d}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    return 0 if d.get("decision") else 4


def cmd_preflight(_args) -> int:
    import requests
    ART.mkdir(parents=True, exist_ok=True)
    try:
        geo = http_json("GET", "https://ipwho.is/", timeout=10)
        country = (geo.get("country_code") or REAL_COUNTRY).upper()
    except Exception:
        country = REAL_COUNTRY
    cands = sorted(set(PHISH_CANDIDATES + WARN_CANDIDATES + LEGIT_FIXED))
    out = {"real_country": country, "probes": []}

    def probe(u):
        row = {"url": u}
        ok, info = dns_resolves((u.split("/")[2]))
        row["dns_resolvable"] = ok
        row["dns_info"] = info
        for tag, uc in (("no_country", None), ("country", country)):
            t0 = now_ms()
            try:
                payload = {"url": u}
                if uc:
                    payload["user_country"] = uc
                r = requests.post(CHECK_ENDPOINT, json=payload, timeout=45)
                row[tag] = {"status": r.status_code,
                            "elapsed_ms": round(now_ms() - t0, 1),
                            "decision": None, "probability": None}
                if r.status_code == 200:
                    j = r.json()
                    row[tag]["decision"] = j.get("decision")
                    row[tag]["probability"] = j.get("probability")
                    row[tag]["brand_mismatch"] = j.get("brand_mismatch")
                    row[tag]["local_suggestions"] = j.get("local_suggestions")
                    row[tag]["geo_context"] = j.get("geo_context")
                    row[tag]["homoglyphs"] = j.get("homoglyphs")
            except Exception as e:
                row[tag] = {"status": None, "elapsed_ms": round(now_ms() - t0, 1),
                            "error": str(e)[:200], "decision": None}
        return row

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as ex:
        for row in ex.map(probe, cands):
            out["probes"].append(row)
            log(f"  probe {row['url'][:65]:65} -> "
                f"{row['no_country'].get('decision')}/{row['country'].get('decision')}")

    def pick(pred, n=3):
        got = [p["url"] for p in out["probes"] if pred(p)]
        return got[:n]

    out["chosen"] = {
        "legitimate": [u for u in LEGIT_FIXED],
        "phishing": pick(lambda p: (p["country"].get("decision") == "phishing")
                         or (p["no_country"].get("decision") == "phishing")),
        "warning": pick(lambda p: (p["country"].get("decision") == "warning")
                        or (p["no_country"].get("decision") == "warning")),
    }
    PREFLIGHT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"chosen: {json.dumps(out['chosen'], indent=2)}")
    return 0


async def run_resolvable_phishing(preflight: dict, branded: dict) -> None:
    """Supplemental battery: phishing-flagged URLs that DO resolve in DNS, so
    the navigation commits and the extension badge/interception path runs.
    Appends to the same requests.jsonl."""
    from playwright.async_api import async_playwright

    pf2_path = ART / "preflight2.json"
    if pf2_path.exists():
        pf2 = json.loads(pf2_path.read_text(encoding="utf-8"))
        phish_urls = [r["url"] for r in pf2
                      if r.get("dns") and r.get("decision") == "phishing"]
    else:
        phish_urls = []
    phish_urls = list(dict.fromkeys(phish_urls))[:7]
    # HTTPS on these parked hosts times out; HTTP (port 80) answers and the
    # navigation commits, which is what the badge path needs. Backend flags
    # the hostname regardless of scheme.
    phish_urls += [
        "http://www.xn--pypal-4ve.com/login",
        "http://www.app1e.com/store",
        "http://santander.com.seguridad.top/login",
    ]

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=False,
            args=[f"--disable-extensions-except={EXT_DIR}",
                  f"--load-extension={EXT_DIR}"],
            ignore_default_args=["--disable-extensions"],
        )
        stop_evt = asyncio.Event()
        sw_ref = [None]
        try:
            if not context.pages:
                await context.new_page()
            page = context.pages[0]
            await page.goto("about:blank")
            sw = await get_sw(context)
            sw_ref[0] = sw
            await sw.evaluate(INSTRUMENT_JS)
            log(f"service worker: {sw.url}")
            ka = asyncio.create_task(keepalive_loop(context, sw_ref, stop_evt))
            rec = Recorder(sw)

            # (c) phishing decisions on resolvable hosts -> expect "!" badge
            #     and warning.html interception where prob >= 0.50
            for u in phish_urls[:5]:
                rec_ = await rec.navigate(page, "c_phishing_resolvable", u, "phishing")
                if rec_["warning_interstitial"]:
                    # go back to a neutral page for the next navigation
                    await page.goto("about:blank")
                    await asyncio.sleep(0.5)

            # (j) homoglyph/punycode regression (BUG-03) on a resolvable host
            puny = [u for u in phish_urls if "xn--" in u]
            for u in puny[:2]:
                r2 = await rec.navigate(page, "j_punycode_resolvable", u, "phishing")
                if r2["warning_interstitial"]:
                    await page.goto("about:blank")
                    await asyncio.sleep(0.5)

            stop_evt.set()
            ka.cancel()
        finally:
            try:
                await context.close()
            except Exception:
                pass
            shutil.rmtree(USER_DATA_DIR, ignore_errors=True)


def cmd_run(_args) -> int:
    pf = json.loads(PREFLIGHT_JSON.read_text(encoding="utf-8"))
    st = load_state()
    backend_pid = st.get("backend_pid")
    log(f"run starting; backend pid={backend_pid} alive={pid_alive(backend_pid or 0)}")
    branded = branded_chrome_refusal_evidence()
    log(f"branded Chrome {branded['branded_chrome_version']}: {branded['refusal_line']}")
    import json as _json  # noqa: F811
    chrome_ver = "Chrome-for-Testing (Playwright chromium-1248)"
    (ART / "chrome_version.txt").write_text(
        f"e2e_browser: {chrome_ver}\n"
        f"branded_chrome_installed: {branded['branded_chrome_version']} "
        f"(refuses --load-extension: {branded['refusal_line']})\n", encoding="utf-8")
    asyncio.run(run_all_scenarios(pf, chrome_ver, branded))
    return 0


def cmd_stub(_args) -> int:
    import http.server
    import socketserver
    import time as _t

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            _t.sleep(30)
            body = b'{"decision":"legitimate","probability":0.0,"stub":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            body = b'{"stub":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", BACKEND_PORT), H) as srv:
        srv.daemon_threads = True
        srv.serve_forever()
    return 0


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    vs = sorted(values)
    if len(vs) == 1:
        return round(vs[0], 2)
    k = (len(vs) - 1) * q
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return round(vs[int(k)], 2)
    return round(vs[f] * (c - k) + vs[c] * (k - f), 2)


def cmd_report(_args) -> int:
    rows = [json.loads(l) for l in REQUESTS_JSONL.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_scn: dict[str, list[dict]] = {}
    for r in rows:
        by_scn.setdefault(r.get("scenario", "?"), []).append(r)

    def api_entries(rec):
        out = []
        for c in rec.get("api_new", []) or []:
            if isinstance(c, dict) and "localhost:8080" in (c.get("url") or ""):
                out.append(c)
        return out

    # The SW performance buffer is re-sliced whole on every navigation, so the
    # same resource-timing entry can appear in several records. Entries are
    # unique by (name, start) within one browser session - dedupe globally.
    seen_rt: set[tuple] = set()
    all_rt_unique: list[float] = []

    def rt_durations(rec):
        durs = []
        for e in rec.get("rt_new", []) or []:
            n = e.get("name", "")
            if "localhost:8080" in n and e.get("dur") is not None:
                key = (n, e.get("start"))
                if key in seen_rt:
                    continue
                seen_rt.add(key)
                durs.append(e["dur"])
                all_rt_unique.append(e["dur"])
        return durs

    summary = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "scenarios": {}, "overall": {}}

    all_api_wrap: list[float] = []
    all_api_rt: list[float] = []
    all_nav2badge: list[float] = []
    all_nav2visible: list[float] = []
    timeouts = 0
    api_total = 0

    for scn, recs in sorted(by_scn.items()):
        wrap, rt, n2b, n2v = [], [], [], []
        badges, decisions, warns, errs = [], [], 0, 0
        navs_with_api = 0
        for rec in recs:
            calls = api_entries(rec)
            navs_with_api += 1 if calls else 0
            for c in calls:
                api_total += 1
                if "error" in c:
                    errs += 1
                    en = c["error"].split(":")[0]
                    if en in ("TimeoutError", "AbortError"):
                        timeouts += 1
                else:
                    wrap.append(c["durMs"])
            rt.extend(rt_durations(rec))
            if rec.get("nav_to_badge_ms") is not None:
                n2b.append(rec["nav_to_badge_ms"])
            if rec.get("nav_to_visible_ms") is not None:
                n2v.append(rec["nav_to_visible_ms"])
            for b in rec.get("badges_new", []) or []:
                badges.append(b.get("text"))
            if rec.get("warning_interstitial"):
                warns += 1
        all_api_wrap.extend(wrap)
        all_api_rt.extend(rt)
        all_nav2badge.extend(n2b)
        all_nav2visible.extend(n2v)
        summary["scenarios"][scn] = {
            "n_reps": len(recs),
            "n_with_backend_call": navs_with_api,
            "badge_texts": sorted(set(str(b) for b in badges)),
            "badge_update_count": len(badges),
            "warning_interstitials": warns,
            "api_errors": errs,
            "api_latency_ms": {k: _pct(wrap, q) for k, q in
                               [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(wrap)},
            "api_latency_resource_timing_ms": {k: _pct(rt, q) for k, q in
                                               [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(rt)},
            "nav_to_badge_ms": {k: _pct(n2b, q) for k, q in
                                [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(n2b)},
            "nav_to_visible_decision_ms": {k: _pct(n2v, q) for k, q in
                                           [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(n2v)},
        }

    summary["overall"] = {
        "api_calls_total": api_total,
        "api_timeouts": timeouts,
        "timeout_rate": round(timeouts / api_total, 4) if api_total else None,
        "api_latency_ms": {k: _pct(all_api_wrap, q) for k, q in
                           [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(all_api_wrap)},
        "api_latency_resource_timing_ms": {k: _pct(all_api_rt, q) for k, q in
                                           [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(all_api_rt)},
        "nav_to_badge_ms": {k: _pct(all_nav2badge, q) for k, q in
                            [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(all_nav2badge)},
        "nav_to_visible_decision_ms": {k: _pct(all_nav2visible, q) for k, q in
                                       [("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99)]} | {"n": len(all_nav2visible)},
    }
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"summary -> {SUMMARY_JSON}")
    print(json.dumps(summary["overall"], indent=2))
    return 0


def cmd_cleanup(_args) -> int:
    st = load_state()
    stop_stub()
    stop_backend()
    pg_pid = st.get("pg_pid")
    if (PG_DATA / "PG_VERSION").exists():
        try:
            cmdline = (f'"{PG_BIN / "pg_ctl"}" -D "{PG_DATA}" -m fast stop')
            _spawn_detached(cmdline)
            log("pg_ctl stop issued (detached)")
        except Exception as e:
            log(f"pg_ctl stop failed: {e}")
    if pg_pid and pid_alive(pg_pid):
        kill_pid_tree(pg_pid)
    shutil.rmtree(USER_DATA_DIR, ignore_errors=True)
    log("cleanup done (throwaway postgres data dir kept for audit; processes stopped)")
    return 0


async def run_failure_modes(branded: dict) -> None:
    """Supplemental battery (run3): timeout / backend-down / offline with the
    improved console serializer so exact error messages land in the logs."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=False,
            args=[f"--disable-extensions-except={EXT_DIR}",
                  f"--load-extension={EXT_DIR}"],
            ignore_default_args=["--disable-extensions"],
        )
        stop_evt = asyncio.Event()
        sw_ref = [None]
        try:
            if not context.pages:
                await context.new_page()
            page = context.pages[0]
            await page.goto("about:blank")
            sw = await get_sw(context)
            sw_ref[0] = sw
            await sw.evaluate(INSTRUMENT_JS)
            log(f"service worker: {sw.url}")
            ka = asyncio.create_task(keepalive_loop(context, sw_ref, stop_evt))
            rec = Recorder(sw)

            # (h) timeout with slow stub, exact console message
            stop_backend()
            start_stub()
            await rec.navigate(
                page, "h_timeout_stub_exact",
                f"https://example.com/?e2e=to2_{random.randint(1000,9999)}", "timeout",
                badge_wait_ms=13000, goto_timeout_ms=30000,
                notes="backend replaced by 30 s-sleep stub; extension aborts at ~8000 ms")
            stop_stub()
            start_backend()
            log(f"  backend restarted healthy={wait_backend_healthy(120)}")

            # (m) backend down, exact console message
            stop_backend()
            await rec.navigate(
                page, "m_backend_down_exact",
                f"https://example.com/?e2e=bd2_{random.randint(1000,9999)}", "error",
                badge_wait_ms=12000,
                notes="backend stopped; must fail safe (no 'legitimate' claim)")
            start_backend()
            log(f"  backend restarted healthy={wait_backend_healthy(120)}")

            # (n) offline
            await context.set_offline(True)
            await rec.navigate(
                page, "n_offline_exact", "https://www.wikipedia.org/?e2e=off2", "error",
                badge_wait_ms=10000, notes="context.set_offline(true)")
            await context.set_offline(False)

            stop_evt.set()
            ka.cancel()
        finally:
            try:
                await context.close()
            except Exception:
                pass
            shutil.rmtree(USER_DATA_DIR, ignore_errors=True)


async def run_screenshots() -> None:
    """run4: capture desktop screenshots at badge-visible moments (browser
    chrome/toolbar is not part of Playwright page screenshots)."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=False,
            args=[f"--disable-extensions-except={EXT_DIR}",
                  f"--load-extension={EXT_DIR}"],
            ignore_default_args=["--disable-extensions"],
        )
        stop_evt = asyncio.Event()
        sw_ref = [None]
        try:
            if not context.pages:
                await context.new_page()
            page = context.pages[0]
            await page.goto("about:blank")
            sw = await get_sw(context)
            sw_ref[0] = sw
            await sw.evaluate(INSTRUMENT_JS)
            rec = Recorder(sw)
            await asyncio.sleep(1.0)
            r = await rec.navigate(page, "shot_legit_badge", "https://example.com/", "legit",
                                   desktop_shot=True, badge_wait_ms=12000)
            await asyncio.sleep(1.0)
            r = await rec.navigate(page, "shot_phishing_badge", "https://www.gogle.com/", "phishing",
                                   desktop_shot=True, badge_wait_ms=12000)
            await asyncio.sleep(1.0)
            if r["warning_interstitial"]:
                pass  # warning interstitial itself was screenshotted by page.screenshot
            await rec.navigate(page, "shot_warning_badge", "http://bcp.com/", "warning",
                               desktop_shot=True, badge_wait_ms=12000)
        finally:
            try:
                await context.close()
            except Exception:
                pass
            shutil.rmtree(USER_DATA_DIR, ignore_errors=True)


def cmd_run2(_args) -> int:
    st = load_state()
    backend_pid = st.get("backend_pid")
    log(f"run2 starting; backend pid={backend_pid} alive={pid_alive(backend_pid or 0)}")
    if not wait_backend_healthy(30):
        log("backend not healthy, restarting")
        start_backend()
        wait_backend_healthy(120)
    branded = {"branded_chrome_version": "155.0.8059.40",
               "refusal_line": "(already captured in branded_chrome_load_extension.log)"}
    asyncio.run(run_resolvable_phishing({}, branded))
    return 0


def cmd_run3(_args) -> int:
    st = load_state()
    backend_pid = st.get("backend_pid")
    log(f"run3 starting; backend pid={backend_pid} alive={pid_alive(backend_pid or 0)}")
    if not wait_backend_healthy(30):
        start_backend()
        wait_backend_healthy(120)
    branded = {"branded_chrome_version": "155.0.8059.40",
               "refusal_line": "(already captured in branded_chrome_load_extension.log)"}
    asyncio.run(run_failure_modes(branded))
    return 0


def cmd_run4(_args) -> int:
    st = load_state()
    if not wait_backend_healthy(30):
        start_backend()
        wait_backend_healthy(120)
    asyncio.run(run_screenshots())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["smoke", "backend-up", "preflight", "run",
                                        "run2", "run3", "run4", "stub", "report",
                                        "cleanup"])
    args = ap.parse_args()
    ART.mkdir(parents=True, exist_ok=True)
    table = {"smoke": cmd_smoke, "backend-up": cmd_backend_up,
             "preflight": cmd_preflight, "run": cmd_run, "run2": cmd_run2,
             "run3": cmd_run3, "run4": cmd_run4,
             "stub": cmd_stub, "report": cmd_report, "cleanup": cmd_cleanup}
    return table[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

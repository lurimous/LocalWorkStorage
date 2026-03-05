#!/usr/bin/env python3
"""
Local Network File Sharing Server
- No authentication; all actions audited by client IP.
- Run: python server.py
- Access: http://<your-ip>:5000
"""

import os
import re
import io
import shutil
import mimetypes
import logging
import platform
import configparser
from pathlib import Path

IMAGE_EXTS = frozenset({'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'})
VIDEO_EXTS = frozenset({'.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg'})

def _find_ffmpeg():
    """Return path to ffmpeg: project folder / ffmpeg subfolder first, then system PATH."""
    for candidate in [_HERE / "ffmpeg" / "ffmpeg.exe", _HERE / "ffmpeg.exe"]:
        if candidate.exists():
            return str(candidate)
    import shutil
    return shutil.which("ffmpeg") or shutil.which("ffmpeg.exe")

from flask import Flask, request, send_file, jsonify, abort, Response
from werkzeug.utils import secure_filename

# ── Configuration ──────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
_cfg = configparser.ConfigParser()
_cfg.read(_HERE / "config.ini", encoding="utf-8")

_base_path = _cfg.get("server", "base_path", fallback="").strip()
BASE_DIR = (
    Path(_base_path).resolve()
    if _base_path
    else (_HERE / _cfg.get("server", "shared_dir", fallback="./shared")).resolve()
)
AUDIT_LOG = (_HERE / _cfg.get("audit",  "log_file",   fallback="./audit.log")).resolve()
_HOST     = _cfg.get("server", "host", fallback="0.0.0.0")
_PORT     = _cfg.getint("server", "port", fallback=5000)
_MAX_GB   = _cfg.getfloat("server", "max_upload_gb", fallback=10)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(_MAX_GB * 1024 ** 3)

# ── Audit logging ──────────────────────────────────────────────────────────────
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
audit_logger.addHandler(_fh)


def audit(action: str, path: str = "", extra: str = ""):
    ip = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
    parts = [ip, action]
    if path:
        parts.append(path)
    if extra:
        parts.append(extra)
    audit_logger.info(" | ".join(parts))


# ── Path security ──────────────────────────────────────────────────────────────
def safe_path(rel: str) -> Path:
    """Resolve rel within BASE_DIR. Abort 400 on traversal attempts."""
    try:
        p = (BASE_DIR / rel.lstrip("/\\")).resolve()
    except Exception:
        abort(400, "Bad path")
    base = str(BASE_DIR)
    s = str(p)
    # Drive roots already end with os.sep (e.g. "C:\"); don't double it.
    base_prefix = base if base.endswith(os.sep) else base + os.sep
    if s != base and not s.startswith(base_prefix):
        abort(400, "Path outside shared directory")
    return p


def to_rel(p: Path) -> str:
    return str(p.relative_to(BASE_DIR)).replace("\\", "/")


def safe_filename(name: str) -> str:
    """Sanitize filename, preserving unicode but removing dangerous chars."""
    name = Path(name).name  # strip any directory components
    name = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]', "_", name)
    name = name.lstrip(". ")
    return name[:255] if name else "file"


# ── API ────────────────────────────────────────────────────────────────────────
@app.route("/api/list")
def api_list():
    path = request.args.get("path", "")
    d = safe_path(path)
    if not d.exists() or not d.is_dir():
        abort(404, "Directory not found")
    def _sort_key(p):
        try:
            return (not p.is_dir(), p.name.lower())
        except OSError:
            return (True, p.name.lower())

    entries = []
    try:
        items = sorted(d.iterdir(), key=_sort_key)
    except PermissionError:
        abort(403, "Permission denied reading directory")
    for item in items:
        try:
            st = item.stat()
            entries.append({
                "name": item.name,
                "path": to_rel(item),
                "is_dir": item.is_dir(),
                "size": st.st_size if item.is_file() else None,
                "modified": st.st_mtime,
                "is_image": item.is_file() and item.suffix.lower() in IMAGE_EXTS,
                "is_video": item.is_file() and item.suffix.lower() in VIDEO_EXTS,
                "has_thumb": item.is_file() and item.suffix.lower() in (IMAGE_EXTS | VIDEO_EXTS),
            })
        except OSError:
            pass
    return jsonify(path=path or "", entries=entries)


@app.route("/api/download")
def api_download():
    path = request.args.get("path", "")
    f = safe_path(path)
    if not f.is_file():
        abort(404, "File not found")
    audit("DOWNLOAD", path)
    mime, _ = mimetypes.guess_type(f.name)
    return send_file(f, mimetype=mime or "application/octet-stream",
                     as_attachment=True, download_name=f.name)


@app.route("/api/upload", methods=["POST"])
def api_upload():
    path = request.args.get("path", "")
    d = safe_path(path)
    if not d.is_dir():
        abort(400, "Target is not a directory")
    files = request.files.getlist("files")
    if not files:
        abort(400, "No files provided")
    uploaded = []
    for file in files:
        name = safe_filename(file.filename or "")
        if not name:
            continue
        dest = d / name
        file.save(dest)
        audit("UPLOAD", f"{path}/{name}".lstrip("/"))
        uploaded.append(name)
    return jsonify(uploaded=uploaded)


@app.route("/api/mkdir", methods=["POST"])
def api_mkdir():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")
    if not path:
        abort(400, "Path required")
    d = safe_path(path)
    if d.exists():
        abort(400, "Already exists")
    d.mkdir(parents=True)
    audit("MKDIR", path)
    return jsonify(ok=True)


@app.route("/api/rename", methods=["POST"])
def api_rename():
    data = request.get_json(silent=True) or {}
    old = data.get("old", "")
    new = data.get("new", "")
    if not old or not new:
        abort(400, "old and new required")
    src = safe_path(old)
    dst = safe_path(new)
    if not src.exists():
        abort(404, "Source not found")
    if dst.exists():
        abort(400, "Destination already exists")
    src.rename(dst)
    audit("RENAME", old, f"-> {new}")
    return jsonify(ok=True)


@app.route("/api/delete", methods=["POST"])
def api_delete():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")
    if not path:
        abort(400, "Path required")
    p = safe_path(path)
    if not p.exists():
        abort(404, "Not found")
    if p.is_dir():
        def _on_error(func, fpath, _):
            os.chmod(fpath, 0o777)
            func(fpath)
        shutil.rmtree(p, onerror=_on_error)
        audit("DELETE_DIR", path)
    else:
        p.unlink()
        audit("DELETE", path)
    return jsonify(ok=True)


@app.route("/api/thumb")
def api_thumb():
    path = request.args.get("path", "")
    f = safe_path(path)
    if not f.is_file():
        abort(404, "File not found")
    ext = f.suffix.lower()
    if ext not in IMAGE_EXTS and ext not in VIDEO_EXTS:
        abort(400, "Not a supported image or video")

    # ── Video thumbnail via ffmpeg ──────────────────────────────────────────
    if ext in VIDEO_EXTS:
        ffmpeg = _find_ffmpeg()
        if not ffmpeg:
            abort(501, "ffmpeg not found. Place ffmpeg.exe in the server folder.")
        import subprocess
        try:
            result = subprocess.run(
                [ffmpeg, "-ss", "00:00:01", "-i", str(f),
                 "-vframes", "1", "-vf", "scale=256:-1",
                 "-f", "image2", "-vcodec", "mjpeg", "pipe:1"],
                capture_output=True, timeout=15
            )
            if result.returncode != 0 or not result.stdout:
                abort(500, "ffmpeg failed to extract frame")
            resp = Response(result.stdout, mimetype="image/jpeg")
            resp.headers["Cache-Control"] = "max-age=3600"
            return resp
        except subprocess.TimeoutExpired:
            abort(500, "ffmpeg timed out")
        except Exception as e:
            abort(500, f"Video thumbnail error: {e}")
    # SVG: serve directly, browsers render natively
    if ext == ".svg":
        resp = send_file(f, mimetype="image/svg+xml")
        resp.headers["Cache-Control"] = "max-age=3600"
        return resp
    try:
        from PIL import Image
        with Image.open(f) as img:
            img.thumbnail((256, 256), Image.LANCZOS)
            buf = io.BytesIO()
            if img.mode in ("RGBA", "P", "LA"):
                img = img.convert("RGBA")
                img.save(buf, format="PNG")
                mime = "image/png"
            else:
                img = img.convert("RGB")
                img.save(buf, format="JPEG", quality=82)
                mime = "image/jpeg"
        buf.seek(0)
        resp = Response(buf.read(), mimetype=mime)
        resp.headers["Cache-Control"] = "max-age=3600"
        return resp
    except ImportError:
        abort(501, "Pillow not installed. Run: pip install Pillow")
    except Exception as e:
        abort(500, f"Thumbnail error: {e}")


@app.route("/api/default_pins")
def api_default_pins():
    if platform.system() != "Windows":
        return jsonify(pins=[])
    profile = os.environ.get("USERPROFILE", "")
    candidates = [
        ("Desktop",   "🖥️",  os.path.join(profile, "Desktop")),
        ("Downloads", "⬇️",  os.path.join(profile, "Downloads")),
        ("Documents", "📋",  os.path.join(profile, "Documents")),
        ("Pictures",  "🖼️",  os.path.join(profile, "Pictures")),
        ("Music",     "🎵",  os.path.join(profile, "Music")),
        ("Videos",    "🎬",  os.path.join(profile, "Videos")),
    ]
    pins = []
    for name, icon, abs_path in candidates:
        p = Path(abs_path)
        if p.exists() and p.is_dir():
            try:
                rel = p.relative_to(BASE_DIR)
                pins.append({"name": name, "icon": icon, "path": str(rel).replace("\\", "/")})
            except ValueError:
                pass  # folder exists but is not under BASE_DIR
    return jsonify(pins=pins)


@app.route("/api/audit")
def api_audit():
    n = min(int(request.args.get("n", 500)), 2000)
    if not AUDIT_LOG.exists():
        return jsonify(lines=[])
    with open(AUDIT_LOG, encoding="utf-8") as f:
        lines = f.readlines()
    return jsonify(lines=[ln.rstrip() for ln in lines[-n:]])


# ── UI ─────────────────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>File Share</title>
<style>
@font-face { font-family: "Outfit";     src: url("/fonts/Outfit-VariableFont_wght.ttf") format("truetype"); font-weight: 100 900; }
@font-face { font-family: "StackSans";  src: url("/fonts/stacksans.ttf")  format("truetype"); font-weight: 100 900; }
@font-face { font-family: "EBGaramond"; src: url("/fonts/EBGaramond.ttf") format("truetype"); font-weight: 400 800; }
@font-face { font-family: "Playwrite";  src: url("/fonts/playwrite.ttf")  format("truetype"); font-weight: 400; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: "StackSans", "Outfit", sans-serif; background: #f5f5f5; color: #000; min-height: 100vh; }

/* ── Top nav (perekaperabot style) ── */
.topnav { background: #000; border-bottom: 1px solid #1a1a1a; position: sticky; top: 0; z-index: 50; transition: box-shadow .3s ease; }
.topnav.nav-scrolled { box-shadow: 0 2px 24px rgba(0,0,0,.45); }
.topnav-inner { max-width: 1280px; margin: 0 auto; padding: 0 32px; height: 68px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }
.nav-brand { display: flex; align-items: center; gap: 14px; cursor: default; flex-shrink: 0; }
.nav-brand-text { display: flex; flex-direction: column; justify-content: center; line-height: 1; }
.nav-brand-name { font-family: "StackSans", sans-serif; font-size: 19px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: #fff; }
.nav-brand-sub  { font-family: "StackSans", sans-serif; font-size: 8.5px; color: #a3a3a3; letter-spacing: .18em; text-transform: uppercase; margin-top: 4px; }
.nav-actions { display: flex; align-items: center; gap: 10px; }
.view-toggle { border-color: #333; }
.view-btn { color: #666; }
.view-btn:hover { background: #1a1a1a; color: #fff; }
.view-btn.active { background: #FFCE1B; color: #000; }
.btn-log { color: #666; border-color: #333; }
.btn-log:hover { background: #1a1a1a; color: #fff; }

.toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.breadcrumb { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; font-size: 14px; flex: 1; min-width: 0; }
.breadcrumb a { color: #000; text-decoration: none; font-weight: 500; cursor: pointer; }
.breadcrumb a:hover { text-decoration: underline; color: #525252; }
.breadcrumb .sep { color: #a3a3a3; }
.breadcrumb .cur { color: #000; font-weight: 600; }

.btn { display: inline-flex; align-items: center; gap: 5px; padding: 7px 14px; border: none; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; transition: background .15s, opacity .15s; text-decoration: none; white-space: nowrap; }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn-primary { background: #FFCE1B; color: #000; }
.btn-primary:hover:not(:disabled) { background: #e6b800; }
.btn-secondary { background: #000; color: #fff; }
.btn-secondary:hover:not(:disabled) { background: #222; }
.btn-danger { background: #ef4444; color: #fff; border: 1px solid #ef4444; }
.btn-danger:hover:not(:disabled) { background: #dc2626; border-color: #dc2626; }
.btn-ghost { background: transparent; color: #525252; border: 1px solid #e5e5e5; }
.btn-ghost:hover:not(:disabled) { background: #f5f5f5; color: #000; }
.btn-sm { padding: 4px 10px; font-size: 12px; }
.btn-log { background: transparent; color: #a3a3a3; border: 1px solid #525252; }
.btn-log:hover { background: #222; color: #fff; }
.btn-back { background: #000; color: #fff; border: 1px solid #000; }
.btn-back:hover:not(:disabled) { background: #333; border-color: #333; }

.view-toggle { display: flex; border: 1px solid #525252; border-radius: 6px; overflow: hidden; }
.view-btn { padding: 6px 12px; background: transparent; border: none; color: #a3a3a3; cursor: pointer; font-size: 13px; font-weight: 500; transition: background .12s, color .12s; }
.view-btn:hover { background: #222; color: #fff; }
.view-btn.active { background: #FFCE1B; color: #000; }

.page-layout { display: flex; min-height: calc(100vh - 68px); }
.sidebar { width: 220px; flex-shrink: 0; background: #fff; border-right: 1px solid #e5e5e5; position: sticky; top: 68px; height: calc(100vh - 68px); overflow-y: auto; display: flex; flex-direction: column; }
.sidebar-header { padding: 18px 16px 8px; font-size: 10px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: #a3a3a3; flex-shrink: 0; }
.pin-item { display: flex; align-items: center; gap: 8px; padding: 9px 14px; font-size: 13px; cursor: pointer; color: #000; transition: background .1s; overflow: hidden; user-select: none; }
.pin-item:hover { background: #f5f5f5; }
.pin-item.pin-active { background: #FFCE1B; font-weight: 600; }
.pin-item.pin-active:hover { background: #e6b800; }
.pin-item-icon { flex-shrink: 0; font-size: 15px; line-height: 1; }
.pin-item-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pin-remove { opacity: 0; flex-shrink: 0; font-size: 16px; line-height: 1; color: #a3a3a3; cursor: pointer; padding: 0 2px; transition: opacity .12s, color .12s; }
.pin-item:hover .pin-remove { opacity: 1; }
.pin-remove:hover { color: #ef4444; }
.pin-empty { padding: 14px 16px; font-size: 12px; color: #a3a3a3; line-height: 1.6; }
.pin-home { font-weight: 600; margin-top: 4px; }
.pin-home.pin-active { background: #FFCE1B; }
.sidebar-sep { height: 1px; background: #e5e5e5; margin: 6px 0; }
.main { flex: 1; min-width: 0; padding: 24px; }

.drop-zone { border: 2px dashed #FFCE1B; border-radius: 10px; padding: 24px; text-align: center; color: #000; margin-bottom: 16px; font-size: 14px; background: #fffde7; transition: background .15s; display: none; }
.drop-zone.drag-over { background: #fff3b0; border-color: #e6b800; }
.drop-zone label { cursor: pointer; text-decoration: underline; }

.upload-progress { margin-bottom: 16px; }
.progress-item { background: #fff; border-radius: 8px; padding: 10px 14px; margin-bottom: 6px; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 13px; }
.progress-item .row { display: flex; justify-content: space-between; margin-bottom: 5px; }
.progress-bar-wrap { background: #e5e5e5; border-radius: 99px; height: 5px; overflow: hidden; }
.progress-bar { background: #FFCE1B; height: 100%; border-radius: 99px; transition: width .15s; }
.progress-item.done .progress-bar { background: #10b981; }
.progress-item.error .progress-bar { background: #ef4444; }

/* ── File container card ── */
.card { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.06); overflow: hidden; }

/* ── List view ── */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
thead th { background: #f5f5f5; font-weight: 600; color: #525252; padding: 11px 16px; text-align: left; border-bottom: 1px solid #e5e5e5; white-space: nowrap; }
tbody tr { border-bottom: 1px solid #f5f5f5; transition: background .08s; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: #f5f5f5; }
td { padding: 9px 16px; vertical-align: middle; }
.td-name { display: flex; align-items: center; gap: 10px; }
.td-name a { color: #000; text-decoration: none; font-weight: 500; cursor: pointer; }
.td-name a:hover { text-decoration: underline; color: #525252; }
.td-actions { display: flex; gap: 5px; justify-content: flex-end; white-space: nowrap; }
.list-icon { width: 22px; height: 22px; flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-size: 18px; line-height: 1; }
.list-icon img { width: 20px; height: 20px; display: block; }
.text-muted { color: #a3a3a3; font-size: 13px; }
.empty-state { text-align: center; padding: 56px; color: #a3a3a3; }
.empty-state .big { font-size: 40px; margin-bottom: 10px; }

/* ── Grid / Thumb view ── */
.grid-wrap { padding: 16px; }
.grid-container { display: grid; grid-template-columns: repeat(auto-fill, minmax(148px, 1fr)); gap: 12px; }
.file-card { position: relative; background: #fff; border-radius: 10px; border: 1px solid #e5e5e5; cursor: pointer; transition: box-shadow .15s, transform .12s; display: flex; flex-direction: column; overflow: hidden; user-select: none; }
.file-card:hover { box-shadow: 0 6px 20px rgba(0,0,0,.1); transform: translateY(-2px); }
.card-preview { display: flex; align-items: center; justify-content: center; height: 110px; background: #f5f5f5; font-size: 52px; line-height: 1; overflow: hidden; flex-shrink: 0; }
.card-preview.folder-bg { background: #fffde7; }
.card-preview img { width: 100%; height: 100%; object-fit: cover; display: block; }
.card-body { padding: 8px 10px 10px; }
.card-name { font-size: 12.5px; font-weight: 500; color: #000; word-break: break-all; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; line-height: 1.35; }
.card-meta { font-size: 11px; color: #a3a3a3; margin-top: 4px; }
.card-actions { position: absolute; top: 6px; right: 6px; display: flex; gap: 3px; opacity: 0; transition: opacity .15s; pointer-events: none; }
.file-card:hover .card-actions { opacity: 1; pointer-events: auto; }
.cab { background: rgba(0,0,0,.72); backdrop-filter: blur(4px); color: #fff; border: none; border-radius: 5px; padding: 4px 8px; font-size: 12px; cursor: pointer; }
.cab:hover { background: rgba(0,0,0,.95); }
.cab.danger { background: rgba(220,38,38,.8); }
.cab.danger:hover { background: rgba(185,28,28,.95); }

/* ── Modals ── */
.modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 100; display: flex; align-items: center; justify-content: center; padding: 16px; }
.modal { background: #fff; border-radius: 12px; padding: 24px; width: 100%; max-width: 440px; box-shadow: 0 20px 60px rgba(0,0,0,.2); }
.modal h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; }
.modal p { font-size: 14px; color: #525252; line-height: 1.5; }
.modal input { width: 100%; padding: 9px 12px; border: 1px solid #e5e5e5; border-radius: 6px; font-size: 14px; outline: none; margin-top: 2px; }
.modal input:focus { border-color: #FFCE1B; box-shadow: 0 0 0 3px rgba(255,206,27,.2); }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 18px; }

.audit-modal { max-width: 760px; }
.audit-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.audit-body { font-family: "Consolas", "Courier New", monospace; font-size: 12px; background: #000; color: #a3a3a3; padding: 12px 14px; border-radius: 8px; height: 420px; overflow-y: auto; white-space: pre; line-height: 1.6; }

.toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 200; display: flex; flex-direction: column; gap: 8px; }
.toast { padding: 11px 18px; border-radius: 8px; font-size: 14px; font-weight: 500; box-shadow: 0 4px 16px rgba(0,0,0,.15); animation: slideIn .2s ease; color: #fff; max-width: 320px; }
.toast.success { background: #10b981; }
.toast.error { background: #ef4444; }
@keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: none; opacity: 1; } }

/* ── Tooltip button ── */
.tip-btn { position: relative; }
.tip-btn::after { content: attr(data-tip); position: absolute; top: calc(100% + 7px); left: 50%; transform: translateX(-50%); background: #000; color: #fff; font-size: 11px; font-family: "Outfit", sans-serif; white-space: nowrap; padding: 5px 10px; border-radius: 5px; pointer-events: none; opacity: 0; transition: opacity .15s; z-index: 10; }
.tip-btn:hover::after { opacity: 1; }

/* ── Context menu ── */
#ctx-menu { position: fixed; background: #fff; border: 1px solid #e5e5e5; border-radius: 8px; box-shadow: 0 8px 32px rgba(0,0,0,.12); z-index: 400; min-width: 168px; padding: 4px 0; display: none; animation: fadeUp .14s cubic-bezier(.22,1,.36,1); }
#ctx-menu li { list-style: none; padding: 9px 16px; font-size: 13px; font-family: "Outfit", sans-serif; cursor: pointer; display: flex; align-items: center; gap: 10px; color: #000; transition: background .1s; user-select: none; }
#ctx-menu li:hover { background: #f5f5f5; }
#ctx-menu li.ctx-danger { color: #ef4444; }
#ctx-menu li.ctx-danger:hover { background: #fff5f5; }
#ctx-menu .ctx-sep { height: 1px; background: #e5e5e5; margin: 4px 8px; }
@keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
@keyframes modalIn { from { opacity: 0; transform: scale(.96) translateY(8px); } to { opacity: 1; transform: none; } }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.main { animation: fadeIn .25s ease; overflow-x: hidden; }
.anim { opacity: 0; animation: fadeUp .3s cubic-bezier(.22,1,.36,1) forwards; }
.modal { animation: modalIn .2s cubic-bezier(.22,1,.36,1); }
.btn { transition: background .15s, opacity .15s, transform .1s, box-shadow .15s; }
.btn:hover:not(:disabled) { transform: translateY(-1px); }
.btn:active:not(:disabled) { transform: translateY(0); }
</style>
</head>
<body>

<nav class="topnav" id="topnav">
  <div class="topnav-inner">
    <div class="nav-brand">
      <div class="nav-brand-text">
        <span class="nav-brand-name">LocalWorkStorage</span>
        <span class="nav-brand-sub">A tool to manage shared files on local network</span>
      </div>
    </div>
    <div class="nav-actions">
      <div class="view-toggle">
        <button class="view-btn" data-view="list" onclick="setView('list')" title="List view">List</button>
        <button class="view-btn" data-view="grid" onclick="setView('grid')" title="Grid view">Grid</button>
        <button class="view-btn" data-view="thumb" onclick="setView('thumb')" title="Thumbnail view">Thumb</button>
      </div>
      <button class="btn btn-log" onclick="openAudit()">Audit Log</button>
    </div>
  </div>
</nav>

<div id="ctx-menu"></div>

<div class="page-layout">
<aside class="sidebar" id="sidebar">
  <div class="pin-item pin-home" id="sidebar-home" onclick="navigate('')">
    <span class="pin-item-icon">🏠</span>
    <span class="pin-item-name">Home</span>
  </div>
  <div class="sidebar-sep"></div>
  <div class="sidebar-header">Pinned Folders</div>
  <div id="pin-list"><p class="pin-empty">No pins yet.<br>Right-click a folder to pin it.</p></div>
</aside>

<div class="main">
  <div class="toolbar">
    <button class="btn btn-ghost btn-back" id="btn-back" onclick="goBack()" style="display:none">&#8592; Back</button>
    <nav class="breadcrumb" id="breadcrumb"></nav>
    <button class="btn btn-primary tip-btn" data-tip="Upload files" onclick="openUpload()">&#8679; Upload</button>
    <button class="btn btn-secondary tip-btn" data-tip="New folder" onclick="openMkdir()">&#43; New Folder</button>
  </div>

  <div id="upload-progress" class="upload-progress"></div>

  <div id="drop-zone" class="drop-zone">
    <div style="font-size:32px;margin-bottom:8px">&#8679;</div>
    Drop files here to upload, or <label for="file-input">browse</label>
    <input type="file" id="file-input" multiple style="display:none" onchange="handleFileInput(this)">
  </div>

  <div id="file-container" class="card"></div>
</div><!-- .main -->
</div><!-- .page-layout -->

<!-- Rename modal -->
<div id="modal-rename" class="modal-backdrop" style="display:none" onclick="closeModal('modal-rename')">
  <div class="modal" onclick="event.stopPropagation()">
    <h2>Rename</h2>
    <input type="text" id="rename-input" placeholder="New name"
           onkeydown="if(event.key==='Enter')doRename(); if(event.key==='Escape')closeModal('modal-rename')">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-rename')">Cancel</button>
      <button class="btn btn-primary" onclick="doRename()">Rename</button>
    </div>
  </div>
</div>

<!-- New folder modal -->
<div id="modal-mkdir" class="modal-backdrop" style="display:none" onclick="closeModal('modal-mkdir')">
  <div class="modal" onclick="event.stopPropagation()">
    <h2>New Folder</h2>
    <input type="text" id="mkdir-input" placeholder="Folder name"
           onkeydown="if(event.key==='Enter')doMkdir(); if(event.key==='Escape')closeModal('modal-mkdir')">
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-mkdir')">Cancel</button>
      <button class="btn btn-primary" onclick="doMkdir()">Create</button>
    </div>
  </div>
</div>

<!-- Delete confirm modal -->
<div id="modal-delete" class="modal-backdrop" style="display:none" onclick="closeModal('modal-delete')">
  <div class="modal" onclick="event.stopPropagation()">
    <h2>Confirm Delete</h2>
    <p id="delete-msg"></p>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-delete')">Cancel</button>
      <button class="btn btn-danger" onclick="doDelete()">Delete</button>
    </div>
  </div>
</div>

<!-- Audit log modal -->
<div id="modal-audit" class="modal-backdrop" style="display:none" onclick="closeModal('modal-audit')">
  <div class="modal audit-modal" onclick="event.stopPropagation()">
    <div class="audit-toolbar">
      <h2>Audit Log</h2>
      <button class="btn btn-ghost btn-sm" onclick="loadAudit()">Refresh</button>
    </div>
    <div class="audit-body" id="audit-body">Loading...</div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-audit')">Close</button>
    </div>
  </div>
</div>

<div class="toast-container" id="toasts"></div>

<script>
let currentPath = '';
let pendingRename = null;
let pendingDelete = null;
let lastEntries = [];
let currentView = localStorage.getItem('fs_view') || 'list';

// ── View toggle ────────────────────────────────────────────────────────────
function setView(v) {
  currentView = v;
  localStorage.setItem('fs_view', v);
  document.querySelectorAll('.view-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.view === v));
  renderFiles(lastEntries);
}

function initViewToggle() {
  document.querySelectorAll('.view-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.view === currentView));
}

// ── Navigation ─────────────────────────────────────────────────────────────
function navigate(path) {
  currentPath = path;
  loadDir(path);
  updateBreadcrumb(path);
  document.getElementById('btn-back').style.display = path ? '' : 'none';
  renderPins();
}

function goBack() {
  var parts = currentPath ? currentPath.split('/') : [];
  parts.pop();
  navigate(parts.join('/'));
}

function updateBreadcrumb(path) {
  const bc = document.getElementById('breadcrumb');
  const parts = path ? path.split('/') : [];
  let html = '<a onclick="navigate(\\'\\')">Home</a>';
  let acc = '';
  parts.forEach((p, i) => {
    acc += (acc ? '/' : '') + p;
    const cap = acc;
    html += '<span class="sep"> / </span>';
    if (i === parts.length - 1) {
      html += '<span class="cur">' + esc(p) + '</span>';
    } else {
      html += '<a data-path="' + esc(cap) + '" onclick="navigate(this.dataset.path)">' + esc(p) + '</a>';
    }
  });
  bc.innerHTML = html;
}

async function loadDir(path) {
  const res = await fetch('/api/list?path=' + encodeURIComponent(path));
  if (!res.ok) { toast('Failed to load directory', 'error'); return; }
  const data = await res.json();
  lastEntries = data.entries;
  renderFiles(lastEntries);
}

function renderFiles(entries) {
  lastEntries = entries;
  if (currentView === 'list') renderList(entries);
  else renderGrid(entries, currentView === 'thumb');
}

// ── List view ──────────────────────────────────────────────────────────────
function renderList(entries) {
  const c = document.getElementById('file-container');
  if (!entries.length) {
    c.innerHTML = '<div class="empty-state"><div class="big">&#128194;</div>This folder is empty</div>';
    return;
  }
  c.innerHTML =
    '<div class="table-wrap"><table>' +
    '<thead><tr>' +
    '<th style="width:99%">Name</th>' +
    '<th style="min-width:90px">Size</th>' +
    '<th style="min-width:160px">Modified</th>' +
    '<th style="min-width:140px;text-align:right">Actions</th>' +
    '</tr></thead><tbody>' +
    entries.map((e, i) => {
      const delay = Math.min(i * 28, 400);
      const icon = e.is_dir ? '&#128193;' : fileIcon(e.name);
      const nameCell = e.is_dir
        ? '<a data-path="' + esc(e.path) + '" onclick="navigate(this.dataset.path)">' + esc(e.name) + '</a>'
        : '<span>' + esc(e.name) + '</span>';
      const size = e.is_dir
        ? '<span class="text-muted">&mdash;</span>'
        : '<span class="text-muted">' + fmtSize(e.size) + '</span>';
      const mod = '<span class="text-muted">' + fmtDate(e.modified) + '</span>';
      const dlBtn = e.is_dir
        ? ''
        : '<a class="btn btn-ghost btn-sm" href="/api/download?path=' + encodeURIComponent(e.path) + '" title="Download">&#8681;</a>';
      const actions =
        dlBtn +
        '<button class="btn btn-ghost btn-sm" data-path="' + esc(e.path) + '" data-name="' + esc(e.name) + '" onclick="openRenameEl(this)" title="Rename">&#9998;</button>' +
        '<button class="btn btn-danger btn-sm" data-path="' + esc(e.path) + '" data-name="' + esc(e.name) + '" data-isdir="' + e.is_dir + '" onclick="openDeleteEl(this)" title="Delete">&#128465;</button>';
      return '<tr class="anim" style="animation-delay:' + delay + 'ms" data-path="' + esc(e.path) + '" data-name="' + esc(e.name) + '" data-isdir="' + e.is_dir + '">' +
        '<td><div class="td-name"><span class="list-icon">' + icon + '</span>' + nameCell + '</div></td>' +
        '<td>' + size + '</td>' +
        '<td>' + mod + '</td>' +
        '<td><div class="td-actions">' + actions + '</div></td>' +
        '</tr>';
    }).join('') +
    '</tbody></table></div>';
}

// ── Grid / Thumb view ──────────────────────────────────────────────────────
function renderGrid(entries, showThumbs) {
  const c = document.getElementById('file-container');
  if (!entries.length) {
    c.innerHTML = '<div class="empty-state"><div class="big">&#128194;</div>This folder is empty</div>';
    return;
  }
  c.innerHTML =
    '<div class="grid-wrap"><div class="grid-container">' +
    entries.map((e, i) => buildCard(e, showThumbs, i)).join('') +
    '</div></div>';
}

function buildCard(e, showThumbs, idx) {
  const delay = Math.min((idx || 0) * 28, 400);

  let preview;
  if (e.is_dir) {
    preview = '<div class="card-preview folder-bg">&#128193;</div>';
  } else if (showThumbs && e.has_thumb) {
    const tUrl = '/api/thumb?path=' + encodeURIComponent(e.path);
    preview = '<div class="card-preview"><img src="' + tUrl + '" loading="lazy" onerror="thumbFail(this)"></div>';
  } else {
    preview = '<div class="card-preview">' + fileIconLg(e.name) + '</div>';
  }

  const ep = esc(e.path);
  const en = esc(e.name);
  const isd = String(e.is_dir);

  const cardData = 'data-path="' + ep + '" data-name="' + en + '" data-isdir="' + isd + '"';
  const clickAttr = e.is_dir
    ? cardData + ' onclick="navigate(this.dataset.path)"'
    : cardData + ' onclick="dl(this.dataset.path)"';

  const dlBtn = e.is_dir
    ? ''
    : '<button class="cab" data-path="' + ep + '" onclick="event.stopPropagation();dl(this.dataset.path)" title="Download">&#8681;</button>';

  const actions =
    '<div class="card-actions">' +
    dlBtn +
    '<button class="cab" data-path="' + ep + '" data-name="' + en + '" onclick="event.stopPropagation();openRenameEl(this)" title="Rename">&#9998;</button>' +
    '<button class="cab danger" data-path="' + ep + '" data-name="' + en + '" data-isdir="' + isd + '" onclick="event.stopPropagation();openDeleteEl(this)" title="Delete">&#128465;</button>' +
    '</div>';

  const meta = e.is_dir
    ? '<span class="card-meta">Folder</span>'
    : '<span class="card-meta">' + fmtSize(e.size) + '</span>';

  return '<div class="file-card anim" style="animation-delay:' + delay + 'ms" ' + clickAttr + '>' +
    preview +
    '<div class="card-body"><div class="card-name">' + esc(e.name) + '</div>' + meta + '</div>' +
    actions +
    '</div>';
}

function dl(path) {
  location.href = '/api/download?path=' + encodeURIComponent(path);
}

function openRenameEl(el) {
  openRename(el.dataset.path, el.dataset.name);
}

function openDeleteEl(el) {
  openDelete(el.dataset.path, el.dataset.name, el.dataset.isdir === 'true');
}

function thumbFail(img) {
  img.parentNode.innerHTML = '<span style="font-size:48px">&#128444;</span>';
}

// ── Upload ─────────────────────────────────────────────────────────────────
function openUpload() {
  const dz = document.getElementById('drop-zone');
  dz.style.display = dz.style.display === 'none' ? 'block' : 'none';
}

function handleFileInput(input) {
  uploadFiles(Array.from(input.files));
  input.value = '';
}

async function uploadFiles(files) {
  if (!files.length) return;
  const progress = document.getElementById('upload-progress');
  for (const file of files) {
    const itemEl = document.createElement('div');
    itemEl.className = 'progress-item';
    itemEl.innerHTML =
      '<div class="row"><span>' + esc(file.name) + '</span><span class="text-muted pct">0%</span></div>' +
      '<div class="progress-bar-wrap"><div class="progress-bar" style="width:0%"></div></div>';
    progress.appendChild(itemEl);
    const fd = new FormData();
    fd.append('files', file);
    try {
      await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload?path=' + encodeURIComponent(currentPath));
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            const pct = Math.round(e.loaded / e.total * 100);
            itemEl.querySelector('.progress-bar').style.width = pct + '%';
            itemEl.querySelector('.pct').textContent = pct + '%';
          }
        };
        xhr.onload = () => xhr.status < 300 ? resolve() : reject(new Error(xhr.responseText));
        xhr.onerror = () => reject(new Error('Network error'));
        xhr.send(fd);
      });
      itemEl.classList.add('done');
      itemEl.querySelector('.pct').textContent = 'Done';
    } catch {
      itemEl.classList.add('error');
      itemEl.querySelector('.pct').textContent = 'Failed';
    }
  }
  setTimeout(() => { progress.innerHTML = ''; }, 3000);
  loadDir(currentPath);
}

// Drag-and-drop
document.addEventListener('DOMContentLoaded', () => {
  const dz = document.getElementById('drop-zone');
  document.body.addEventListener('dragover', e => {
    e.preventDefault();
    dz.style.display = 'block';
    dz.classList.add('drag-over');
  });
  document.body.addEventListener('dragleave', e => {
    if (!e.relatedTarget || !document.body.contains(e.relatedTarget)) {
      dz.classList.remove('drag-over');
    }
  });
  document.body.addEventListener('drop', e => {
    e.preventDefault();
    dz.classList.remove('drag-over');
    uploadFiles(Array.from(e.dataTransfer.files));
  });
  initViewToggle();
  loadDefaultPins();
  navigate('');
});

// ── New Folder ─────────────────────────────────────────────────────────────
function openMkdir() {
  document.getElementById('mkdir-input').value = '';
  document.getElementById('modal-mkdir').style.display = 'flex';
  setTimeout(() => document.getElementById('mkdir-input').focus(), 50);
}

async function doMkdir() {
  const name = document.getElementById('mkdir-input').value.trim();
  if (!name) return;
  const path = currentPath ? currentPath + '/' + name : name;
  const res = await fetch('/api/mkdir', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path })
  });
  closeModal('modal-mkdir');
  if (res.ok) { toast('Folder created'); loadDir(currentPath); }
  else { const d = await res.json().catch(() => ({})); toast(d.description || 'Failed', 'error'); }
}

// ── Rename ─────────────────────────────────────────────────────────────────
function openRename(path, name) {
  pendingRename = path;
  const input = document.getElementById('rename-input');
  input.value = name;
  document.getElementById('modal-rename').style.display = 'flex';
  setTimeout(() => { input.focus(); input.select(); }, 50);
}

async function doRename() {
  const newName = document.getElementById('rename-input').value.trim();
  if (!newName || !pendingRename) return;
  const parts = pendingRename.split('/');
  parts[parts.length - 1] = newName;
  const newPath = parts.join('/');
  const res = await fetch('/api/rename', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ old: pendingRename, new: newPath })
  });
  closeModal('modal-rename');
  if (res.ok) { toast('Renamed'); loadDir(currentPath); }
  else { const d = await res.json().catch(() => ({})); toast(d.description || 'Rename failed', 'error'); }
}

// ── Delete ─────────────────────────────────────────────────────────────────
function openDelete(path, name, isDir) {
  pendingDelete = path;
  document.getElementById('delete-msg').innerHTML = isDir
    ? 'Delete folder <strong>' + esc(name) + '</strong> and all its contents?'
    : 'Delete file <strong>' + esc(name) + '</strong>?';
  document.getElementById('modal-delete').style.display = 'flex';
}

async function doDelete() {
  if (!pendingDelete) return;
  const res = await fetch('/api/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: pendingDelete })
  });
  closeModal('modal-delete');
  if (res.ok) { toast('Deleted'); loadDir(currentPath); }
  else { toast('Delete failed', 'error'); }
}

// ── Audit Log ──────────────────────────────────────────────────────────────
function openAudit() {
  document.getElementById('modal-audit').style.display = 'flex';
  loadAudit();
}

async function loadAudit() {
  const body = document.getElementById('audit-body');
  body.textContent = 'Loading...';
  const res = await fetch('/api/audit?n=500');
  const data = await res.json();
  if (!data.lines.length) { body.textContent = 'No audit entries yet.'; return; }
  body.innerHTML = data.lines.slice().reverse().map(line => {
    const p = line.split(' | ');
    if (p.length >= 3) {
      return '<span style="color:#475569">' + esc(p[0]) + '</span>'
        + ' | <span style="color:#7dd3fc">' + esc(p[1]) + '</span>'
        + ' | <span style="color:#86efac">' + esc(p[2]) + '</span>'
        + p.slice(3).map(x => ' | <span style="color:#e2e8f0">' + esc(x) + '</span>').join('');
    }
    return esc(line);
  }).join('\\n');
}

// ── Helpers ────────────────────────────────────────────────────────────────
function closeModal(id) {
  document.getElementById(id).style.display = 'none';
}

function toast(msg, type = 'success') {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtSize(n) {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + '\u00a0' + u[i];
}

function fmtDate(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

var _ICON_EXTS = new Set(['aac','ai','aiff','avi','bmp','c','cpp','css','csv','dat','dmg',
  'doc','dotx','dwg','dxf','eps','exe','flv','gif','h','hpp','html','ics','iso',
  'java','jpg','js','key','less','mid','mp3','mp4','mpg','odf','ods','odt','otp',
  'ots','ott','pdf','php','png','ppt','psd','py','qt','rar','rb','rtf','sass',
  'scss','sql','tga','tgz','tiff','txt','wav','xls','xlsx','xml','yml','zip']);
function _iconFile(name) {
  var ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  return _ICON_EXTS.has(ext) ? ext : '_page';
}
function fileIcon(name) {
  var f = _iconFile(name);
  return '<img src="/icons/32px/' + f + '.png" width="20" height="20">';
}
function fileIconLg(name) {
  var f = _iconFile(name);
  return '<img src="/icons/48px/' + f + '.png" width="52" height="52" style="object-fit:contain">';
}

// ── Pin system ─────────────────────────────────────────────────────────────
var _pins = JSON.parse(localStorage.getItem('fs_pins') || '[]');

function _savePins() { localStorage.setItem('fs_pins', JSON.stringify(_pins)); }

function isPinned(path) {
  return _pins.some(function(p) { return p.path === path; });
}

function addPin(path, name) {
  if (!isPinned(path)) {
    _pins.push({ path: path, name: name });
    _savePins();
    renderPins();
    toast('Pinned: ' + name, 'success');
  }
}

function removePin(path) {
  _pins = _pins.filter(function(p) { return p.path !== path; });
  _savePins();
  renderPins();
}

function removePinEl(el) {
  removePin(el.closest('.pin-item').dataset.path);
}

function renderPins() {
  // Home highlight
  document.getElementById('sidebar-home').classList.toggle('pin-active', currentPath === '');

  var el = document.getElementById('pin-list');
  if (!_pins.length) {
    el.innerHTML = '<p class="pin-empty">No pins yet.<br>Right-click a folder to pin it.</p>';
    return;
  }
  el.innerHTML = _pins.map(function(p) {
    var active = p.path === currentPath ? ' pin-active' : '';
    var icon = p.icon || '&#128193;';
    return '<div class="pin-item' + active + '" data-path="' + esc(p.path) + '" onclick="navigate(this.dataset.path)">' +
      '<span class="pin-item-icon">' + icon + '</span>' +
      '<span class="pin-item-name">' + esc(p.name || p.path.split('/').pop() || 'Root') + '</span>' +
      '<span class="pin-remove" onclick="event.stopPropagation();removePinEl(this)" title="Unpin">&times;</span>' +
      '</div>';
  }).join('');
}

async function loadDefaultPins() {
  if (_pins.length) return;
  try {
    var res = await fetch('/api/default_pins');
    if (!res.ok) return;
    var data = await res.json();
    if (data.pins && data.pins.length) {
      _pins = data.pins;
      _savePins();
      renderPins();
    }
  } catch (e) {}
}

// ── Right-click context menu ────────────────────────────────────────────────
var _ctx = null;

function _showCtx(x, y, items) {
  var m = document.getElementById('ctx-menu');
  m.innerHTML = items.map(function(it) {
    if (it === '-') return '<div class="ctx-sep"></div>';
    return '<li class="' + (it.danger ? 'ctx-danger' : '') + '" onclick="' + it.fn + '()">' + it.icon + ' ' + it.label + '</li>';
  }).join('');
  m.style.display = 'block';
  requestAnimationFrame(function() {
    var mw = m.offsetWidth, mh = m.offsetHeight;
    m.style.left = Math.min(x, window.innerWidth  - mw - 8) + 'px';
    m.style.top  = Math.min(y, window.innerHeight - mh - 8) + 'px';
  });
}

function _hideCtx() {
  document.getElementById('ctx-menu').style.display = 'none';
  _ctx = null;
}

function ctxOpen()     { if (_ctx) navigate(_ctx.path); _hideCtx(); }
function ctxDownload() { if (_ctx) dl(_ctx.path);       _hideCtx(); }
function ctxRename()   { if (_ctx) openRename(_ctx.path, _ctx.name); _hideCtx(); }
function ctxDelete()   { if (_ctx) openDelete(_ctx.path, _ctx.name, _ctx.isDir); _hideCtx(); }
function ctxUpload()   { openUpload(); _hideCtx(); }
function ctxMkdir()    { openMkdir();  _hideCtx(); }
function ctxPin()      { if (_ctx) addPin(_ctx.path, _ctx.name); _hideCtx(); }
function ctxUnpin()    { if (_ctx) removePin(_ctx.path); _hideCtx(); }

document.addEventListener('contextmenu', function(e) {
  var item = e.target.closest('tr[data-path], .file-card[data-path]');
  e.preventDefault();
  if (item) {
    _ctx = { path: item.dataset.path, name: item.dataset.name, isDir: item.dataset.isdir === 'true' };
    var pinEntry = isPinned(_ctx.path)
      ? { icon: '📌', label: 'Unpin folder', fn: 'ctxUnpin' }
      : { icon: '📌', label: 'Pin folder',   fn: 'ctxPin'   };
    _showCtx(e.clientX, e.clientY, _ctx.isDir
      ? [
          { icon: '📂', label: 'Open',   fn: 'ctxOpen' },
          pinEntry,
          '-',
          { icon: '✏️', label: 'Rename', fn: 'ctxRename' },
          { icon: '🗑️', label: 'Delete', fn: 'ctxDelete', danger: true },
        ]
      : [
          { icon: '⬇️', label: 'Download', fn: 'ctxDownload' },
          '-',
          { icon: '✏️', label: 'Rename',   fn: 'ctxRename' },
          { icon: '🗑️', label: 'Delete',   fn: 'ctxDelete', danger: true },
        ]);
  } else {
    _ctx = null;
    _showCtx(e.clientX, e.clientY, [
      { icon: '⬆️', label: 'Upload files', fn: 'ctxUpload' },
      { icon: '📁', label: 'New folder',   fn: 'ctxMkdir'  },
    ]);
  }
});

document.addEventListener('click', function(e) {
  if (!e.target.closest('#ctx-menu')) _hideCtx();
});
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') _hideCtx(); });
window.addEventListener('scroll', _hideCtx, true);
window.addEventListener('scroll', function() {
  document.getElementById('topnav').classList.toggle('nav-scrolled', window.scrollY > 10);
});
</script>
</body>
</html>"""


@app.route("/fonts/<path:filename>")
def serve_font(filename):
    return send_file(_HERE / "fonts" / filename, mimetype="font/ttf")


@app.route("/icons/<path:filename>")
def serve_icon(filename):
    return send_file(_HERE / "icons" / filename)


@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    BASE_DIR.mkdir(exist_ok=True)

    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    print(f"\n  File Share Server")
    print(f"  {'─' * 36}")
    print(f"  Shared folder : {BASE_DIR}")
    print(f"  Audit log     : {AUDIT_LOG.resolve()}")
    print(f"  Local         : http://localhost:{_PORT}")
    print(f"  Network       : http://{local_ip}:{_PORT}")
    print(f"\n  Press Ctrl+C to stop.\n")

    app.run(host=_HOST, port=_PORT, debug=False)

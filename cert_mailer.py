"""
CertMailer — Daily polling version
------------------------------------
Checks Canvas once a day for newly completed students and emails them
their certificate. No webhook or admin access required.

Environment variables (set in Railway):
    CANVAS_URL          e.g. https://canvas.eee.uci.edu
    CANVAS_TOKEN        Canvas API token
    CANVAS_COURSE_ID    Numeric course ID from the Canvas URL
    MAILGUN_API_KEY     Mailgun API key
    MAILGUN_DOMAIN      e.g. sandbox-abc123.mailgun.org
    FROM_EMAIL          Your verified sender email
    CERT_IMAGE_PATH     e.g. VCA_Cert_2026.png
"""

import os
import io
import logging
import sqlite3
import time
import threading
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, jsonify
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import landscape, A4
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image as RLImage

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CANVAS_URL       = os.environ["CANVAS_URL"].rstrip("/")
CANVAS_TOKEN     = os.environ["CANVAS_TOKEN"]
CANVAS_COURSE_ID = os.environ["CANVAS_COURSE_ID"]
MAILGUN_API_KEY  = os.environ["MAILGUN_API_KEY"]
MAILGUN_DOMAIN   = os.environ["MAILGUN_DOMAIN"]
FROM_EMAIL       = os.environ["FROM_EMAIL"]
CERT_IMAGE_PATH  = os.environ.get("CERT_IMAGE_PATH", "VCA_Cert_2026.png")

NAME_X_PCT  = 0.50
NAME_Y_PCT  = 0.63
NAME_SIZE   = 80
NAME_COLOR  = (30, 26, 22)

DB_PATH    = "cert_log.db"
POLL_HOURS = 24

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS sent_certs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   TEXT NOT NULL,
            course_id TEXT NOT NULL,
            email     TEXT NOT NULL,
            name      TEXT NOT NULL,
            sent_at   TEXT NOT NULL,
            UNIQUE(user_id, course_id)
        )
    """)
    con.commit()
    con.close()

def already_sent(user_id: str, course_id: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT 1 FROM sent_certs WHERE user_id=? AND course_id=?",
        (str(user_id), str(course_id))
    ).fetchone()
    con.close()
    return row is not None

def record_sent(user_id: str, course_id: str, email: str, name: str):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR IGNORE INTO sent_certs (user_id, course_id, email, name, sent_at) VALUES (?,?,?,?,?)",
        (str(user_id), str(course_id), email, name, datetime.utcnow().isoformat())
    )
    con.commit()
    con.close()

def get_sent_log() -> list:
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT name, email, sent_at FROM sent_certs ORDER BY sent_at DESC"
    ).fetchall()
    con.close()
    return [{"name": r[0], "email": r[1], "sent_at": r[2]} for r in rows]

# ---------------------------------------------------------------------------
# Canvas API helpers
# ---------------------------------------------------------------------------

def canvas_get(path: str, params: dict = None) -> dict:
    """Single GET — for endpoints returning a single object (dict)."""
    resp = requests.get(
        f"{CANVAS_URL}/api/v1/{path}",
        headers={"Authorization": f"Bearer {CANVAS_TOKEN}"},
        params=params or {},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()

def canvas_get_all(path: str, params: dict = None) -> list:
    """
    Paginated GET — follows Canvas Link header pagination to fetch all results.
    UCI Canvas uses Link headers, not page= parameters.
    """
    results = []
    url = f"{CANVAS_URL}/api/v1/{path}"
    next_params = dict(params or {})
    next_params.setdefault("per_page", 100)

    while url:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {CANVAS_TOKEN}"},
            params=next_params,
            timeout=15,
        )
        resp.raise_for_status()
        results.extend(resp.json())

        # After first request, next URL already has params encoded
        next_params = {}
        url = None
        for part in resp.headers.get("Link", "").split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                break

    return results

# ---------------------------------------------------------------------------
# Canvas business logic
# ---------------------------------------------------------------------------

def get_course_name() -> str:
    course = canvas_get(f"courses/{CANVAS_COURSE_ID}")
    return course.get("name", "your course")

def get_all_modules() -> list:
    return canvas_get_all(f"courses/{CANVAS_COURSE_ID}/modules")

def student_completed_all_modules(user_id: str, modules: list) -> bool:
    """Returns True if the student has completed every module that has requirements."""
    for module in modules:
        module_id = module.get("id")
        if not module.get("completion_requirements"):
            continue  # skip modules with no requirements
        try:
            detail = canvas_get(
                f"courses/{CANVAS_COURSE_ID}/modules/{module_id}",
                params={"student_id": user_id}
            )
            if detail.get("state", "") != "completed":
                return False
        except requests.HTTPError:
            return False
    return True

def get_completed_students() -> list:
    """Returns all students who have completed all course modules."""
    modules = get_all_modules()
    if not modules:
        log.warning("No modules found for course %s.", CANVAS_COURSE_ID)
        return []
    log.info("Found %d module(s) to check.", len(modules))

    enrollments = canvas_get_all(
        f"courses/{CANVAS_COURSE_ID}/enrollments",
        params={"type[]": "StudentEnrollment", "state[]": "active"}
    )
    log.info("Checking %d enrolled student(s).", len(enrollments))

    students = []
    for enrollment in enrollments:
        user_id = enrollment.get("user_id")
        user    = enrollment.get("user", {})
        name    = user.get("name", "")
        email   = user.get("login_id", "")
        try:
            if name and email and student_completed_all_modules(str(user_id), modules):
                students.append({"user_id": str(user_id), "name": name, "email": email})
                log.info("Completed: %s", name)
        except Exception as e:
            log.warning("Could not check user %s: %s", user_id, e)

    return students

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def load_font(size: int):
    candidates = [
        "palatino.ttf",
        "georgia.ttf",
        "/usr/share/fonts/truetype/msttcorefonts/Georgia.ttf",
        "/Library/Fonts/Georgia.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    log.warning("No font file found — using PIL default. Add palatino.ttf to your repo.")
    return ImageFont.load_default()

def generate_cert_pdf(student_name: str) -> bytes:
    img  = Image.open(CERT_IMAGE_PATH).convert("RGB")
    draw = ImageDraw.Draw(img)
    font = load_font(NAME_SIZE)

    x = img.width  * NAME_X_PCT
    y = img.height * NAME_Y_PCT

    bbox   = draw.textbbox((0, 0), student_name, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    draw.text((x - text_w / 2, y - text_h / 2), student_name, font=font, fill=NAME_COLOR)

    page_w, page_h = landscape(A4)
    aspect = img.width / img.height
    fit_w  = page_w
    fit_h  = page_w / aspect
    if fit_h > page_h:
        fit_h = page_h
        fit_w = page_h * aspect

    img_buf = io.BytesIO()
    img.save(img_buf, format="JPEG", quality=95)
    img_buf.seek(0)

    pdf_buf = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buf,
        pagesize=landscape(A4),
        leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0,
    )
    rl_img = RLImage(ImageReader(img_buf), width=fit_w, height=fit_h)
    rl_img.hAlign = "CENTER"
    doc.build(
        [rl_img],
        onFirstPage=lambda c, d: c.translate((page_w - fit_w) / 2, (page_h - fit_h) / 2),
    )
    return pdf_buf.getvalue()

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def send_cert_email(to_email: str, student_name: str, course_name: str, pdf_bytes: bytes):
    filename = f"certificate_{student_name.replace(' ', '_')}.pdf"
    response = requests.post(
        f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
        auth=("api", MAILGUN_API_KEY),
        data={
            "from":    f"Course Certificates <{FROM_EMAIL}>",
            "to":      to_email,
            "subject": f"Congratulations! Your certificate for {course_name}",
            "html":    f"""
                <p>Hi {student_name},</p>
                <p>Congratulations on completing <strong>{course_name}</strong>!</p>
                <p>Please find your certificate attached to this email.</p>
                <p>Well done!</p>
            """,
        },
        files=[("attachment", (filename, pdf_bytes, "application/pdf"))],
        timeout=15,
    )
    response.raise_for_status()
    log.info("Email sent to %s — status %s", to_email, response.status_code)

# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

def run_poll():
    log.info("--- Poll started at %s ---", datetime.utcnow().isoformat())
    try:
        course_name = get_course_name()
        log.info("Course: %s", course_name)

        completed = get_completed_students()
        log.info("Found %d completed student(s).", len(completed))

        sent_count = 0
        for student in completed:
            uid   = student["user_id"]
            name  = student["name"]
            email = student["email"]

            if already_sent(uid, CANVAS_COURSE_ID):
                log.info("Already sent to %s — skipping.", name)
                continue

            log.info("Generating certificate for %s (%s)...", name, email)
            pdf_bytes = generate_cert_pdf(name)
            send_cert_email(email, name, course_name, pdf_bytes)
            record_sent(uid, CANVAS_COURSE_ID, email, name)
            sent_count += 1
            time.sleep(1)

        log.info("Poll complete. Sent %d new certificate(s).", sent_count)

    except Exception as e:
        log.exception("Poll failed: %s", e)

def polling_loop():
    while True:
        run_poll()
        log.info("Next poll in %d hours.", POLL_HOURS)
        time.sleep(POLL_HOURS * 3600)

# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "poll_hours": POLL_HOURS}), 200

@app.route("/poll", methods=["POST"])
def manual_poll():
    thread = threading.Thread(target=run_poll, daemon=True)
    thread.start()
    return jsonify({"status": "poll started"}), 200

@app.route("/log", methods=["GET"])
def sent_log():
    return jsonify(get_sent_log()), 200

# ---------------------------------------------------------------------------
# Startup — runs whether launched via gunicorn or directly
# ---------------------------------------------------------------------------

init_db()
poll_thread = threading.Thread(target=polling_loop, daemon=True)
poll_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    log.info("CertMailer starting on port %d", port)
    app.run(host="0.0.0.0", port=port)
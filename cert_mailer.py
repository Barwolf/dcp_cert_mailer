"""
CertMailer — Daily polling version
------------------------------------
Checks Canvas once a day for newly completed students and emails them
their certificate. No webhook or admin access required.

Requirements:
    pip install -r requirements.txt

Environment variables (set in Railway):
    CANVAS_URL          e.g. https://canvas.eee.uci.edu
    CANVAS_TOKEN        Canvas API token
    CANVAS_COURSE_ID    The numeric ID of your course (see below)
    MAILGUN_API_KEY     Mailgun API key
    MAILGUN_DOMAIN      e.g. sandbox-abc123.mailgun.org
    FROM_EMAIL          Your verified sender email
    CERT_IMAGE_PATH     e.g. VCA_Cert_2026.png

How to find your CANVAS_COURSE_ID:
    Go to your course in Canvas — the number in the URL is the course ID.
    e.g. canvas.eee.uci.edu/courses/12345  →  CANVAS_COURSE_ID=12345
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

# Name position — adjust to match your certificate template.
# Use the HTML tool to find the right X/Y percentages first.
NAME_X_PCT  = 0.50
NAME_Y_PCT  = 0.63   
NAME_SIZE   = 80     
NAME_COLOR  = (30, 26, 22)

DB_PATH      = "cert_log.db"
POLL_HOURS   = 24   # how often to check Canvas (in hours)

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
# Canvas API
# ---------------------------------------------------------------------------

def canvas_get(path: str, params: dict = None) -> dict | list:
    resp = requests.get(
        f"{CANVAS_URL}/api/v1/{path}",
        headers={"Authorization": f"Bearer {CANVAS_TOKEN}"},
        params=params or {},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()

def get_course_name() -> str:
    course = canvas_get(f"courses/{CANVAS_COURSE_ID}")
    return course.get("name", "your course")

def get_completed_students() -> list:
    """
    Returns a list of students who have completed all course requirements.
    Uses the Canvas course completions endpoint.
    """
    students = []
    page = 1

    while True:
        # Get all enrollments for the course
        enrollments = canvas_get(
            f"courses/{CANVAS_COURSE_ID}/enrollments",
            params={
                "type[]": "StudentEnrollment",
                "state[]": "active",
                "per_page": 100,
                "page": page,
            }
        )

        if not enrollments:
            break

        for enrollment in enrollments:
            user_id = enrollment.get("user_id")
            user    = enrollment.get("user", {})
            name    = user.get("name", "")
            email   = user.get("login_id", "")  # usually their email at UCI

            # Check completion via course progress
            try:
                progress = canvas_get(f"courses/{CANVAS_COURSE_ID}/users/{user_id}/course_progress")
                req_count     = progress.get("requirement_count", 0)
                req_completed = progress.get("requirement_completed_count", 0)
                completed_at  = progress.get("completed_at")

                # Student is complete if all requirements are met
                is_complete = (
                    req_count > 0 and
                    req_completed >= req_count
                ) or completed_at is not None

                if is_complete and name and email:
                    students.append({
                        "user_id": str(user_id),
                        "name":    name,
                        "email":   email,
                    })

            except requests.HTTPError as e:
                log.warning("Could not get progress for user %s: %s", user_id, e)
                continue

        if len(enrollments) < 100:
            break
        page += 1

    return students

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def load_font(size: int):
    candidates = [
    "palatino.ttf",
    "palab.ttf",
    "pala.ttf",
    "/usr/share/fonts/truetype/msttcorefonts/Palatino.ttf",
    "/Library/Fonts/Palatino.ttc",
    "georgia.ttf",   # fallback
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    log.warning("Georgia not found — using default font. Add georgia.ttf to your repo.")
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
    log.info("Email sent to %s — Mailgun status %s", to_email, response.status_code)

# ---------------------------------------------------------------------------
# Main polling loop
# ---------------------------------------------------------------------------

def run_poll():
    """Check Canvas for completed students and send certs as needed."""
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
            time.sleep(1)  # small pause between emails

        log.info("Poll complete. Sent %d new certificate(s).", sent_count)

    except Exception as e:
        log.exception("Poll failed: %s", e)

def polling_loop():
    """Background thread — runs once on startup, then every POLL_HOURS hours."""
    while True:
        run_poll()
        log.info("Next poll in %d hours.", POLL_HOURS)
        time.sleep(POLL_HOURS * 3600)

# ---------------------------------------------------------------------------
# Flask routes (for Railway health checks + manual controls)
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "next_poll_hours": POLL_HOURS}), 200

@app.route("/poll", methods=["POST"])
def manual_poll():
    """Trigger a manual poll immediately — useful for testing."""
    thread = threading.Thread(target=run_poll, daemon=True)
    thread.start()
    return jsonify({"status": "poll started"}), 200

@app.route("/log", methods=["GET"])
def sent_log():
    """See everyone who has been sent a certificate."""
    return jsonify(get_sent_log()), 200

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
init_db()


if __name__ == "__main__":

    # Start the background polling thread
    poll_thread = threading.Thread(target=polling_loop, daemon=True)
    poll_thread.start()

    port = int(os.environ.get("PORT", 8080))
    log.info("CertMailer polling every %d hours. Starting Flask on port %d.", POLL_HOURS, port)
    app.run(host="0.0.0.0", port=port)
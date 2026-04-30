"""
CertMailer — Daily polling version
------------------------------------
Checks Canvas once a day for students who passed the final quiz
and emails them their certificate automatically.

Environment variables (set in Railway):
    CANVAS_URL          e.g. https://canvas.eee.uci.edu
    CANVAS_TOKEN        Canvas API token
    CANVAS_COURSE_ID    e.g. 80782
    CANVAS_QUIZ_ID      e.g. 424718
    QUIZ_PASSING_SCORE  Minimum score to pass (e.g. 28 for 80% of 35pts)
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
from reportlab.lib.utils import ImageReader

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CANVAS_URL          = os.environ["CANVAS_URL"].rstrip("/")
CANVAS_TOKEN        = os.environ["CANVAS_TOKEN"]
CANVAS_COURSE_ID    = os.environ["CANVAS_COURSE_ID"]
CANVAS_QUIZ_ID      = os.environ["CANVAS_QUIZ_ID"]
QUIZ_PASSING_SCORE  = float(os.environ.get("QUIZ_PASSING_SCORE", "28"))
MAILGUN_API_KEY     = os.environ["MAILGUN_API_KEY"]
MAILGUN_DOMAIN      = os.environ["MAILGUN_DOMAIN"]
FROM_EMAIL          = os.environ["FROM_EMAIL"]
CERT_IMAGE_PATH     = os.environ.get("CERT_IMAGE_PATH", "VCA_Cert_2026.png")

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
    """Single GET for endpoints returning one object."""
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
    Paginated GET — follows Canvas Link header pagination.
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
        data = resp.json()
        # Canvas sometimes returns a single dict instead of a list
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict):
            results.append(data)

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

def get_passing_students() -> list:
    """
    Fetch all quiz submissions for the final quiz and return students
    who scored at or above QUIZ_PASSING_SCORE on their best attempt.
    """
    log.info(
        "Checking quiz %s for submissions with score >= %.1f",
        CANVAS_QUIZ_ID, QUIZ_PASSING_SCORE
    )

    # Canvas quiz submissions endpoint returns a wrapper dict with
    # quiz_submissions + users keys. Flatten them out.
    raw = canvas_get_all(
        f"courses/{CANVAS_COURSE_ID}/quizzes/{CANVAS_QUIZ_ID}/submissions",
        params={"include[]": "user"}
    )

    log.info("Raw response has %d item(s). First item type: %s. Keys: %s",
        len(raw),
        type(raw[0]).__name__ if raw else "N/A",
        list(raw[0].keys()) if raw and isinstance(raw[0], dict) else "N/A"
    )

    submissions = []
    users_by_id = {}
    for item in raw:
        if isinstance(item, dict) and "quiz_submissions" in item:
            submissions.extend(item.get("quiz_submissions", []))
            for u in item.get("users", []):
                users_by_id[str(u["id"])] = u
        elif isinstance(item, dict) and "quiz_submissions" not in item:
            submissions.append(item)

    log.info("After parsing: %d submission(s), %d user(s) in lookup.", len(submissions), len(users_by_id))

    log.info("Found %d submission(s) total.", len(submissions))

    passing = []
    for sub in submissions:
        if not isinstance(sub, dict):
            log.warning("Skipping unexpected type: %s", type(sub))
            continue

        uid_str  = str(sub.get("user_id", ""))
        user     = sub.get("user") or users_by_id.get(uid_str, {})
        score    = sub.get("kept_score")
        if score is None:
            score = sub.get("score", 0)
        name     = user.get("name", "")
        email    = user.get("login_id", "")
        workflow = sub.get("workflow_state", "")

        log.info("Student: %s | Score: %s | State: %s", name, score, workflow)

        if workflow in ("complete", "pending_review") and score is not None and float(score) >= QUIZ_PASSING_SCORE:
            if name and email:
                passing.append({
                    "user_id": uid_str,
                    "name":    name,
                    "email":   email,
                    "score":   score,
                })

    return passing

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
    x_off = (page_w - fit_w) / 2
    y_off = (page_h - fit_h) / 2

    img_buf = io.BytesIO()
    img.save(img_buf, format="JPEG", quality=95)
    img_buf.seek(0)

    pdf_buf = io.BytesIO()
    from reportlab.pdfgen import canvas as rl_canvas
    c = rl_canvas.Canvas(pdf_buf, pagesize=landscape(A4))
    c.drawImage(ImageReader(img_buf), x_off, y_off, width=fit_w, height=fit_h)
    c.save()
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

        passing = get_passing_students()
        log.info("Found %d student(s) who passed the quiz.", len(passing))

        sent_count = 0
        for student in passing:
            uid   = student["user_id"]
            name  = student["name"]
            email = student["email"]
            score = student["score"]

            if already_sent(uid, CANVAS_COURSE_ID):
                log.info("Already sent to %s — skipping.", name)
                continue

            log.info("Generating certificate for %s (score: %s)...", name, score)
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
        today = datetime.utcnow().day
        if today == 19:
            log.info("Today is the 19th — running poll.")
            run_poll()
        else:
            log.info("Today is the %d — not the 19th, skipping poll.", today)
        log.info("Sleeping 24 hours before next check.")
        time.sleep(24 * 3600)

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
# Startup
# ---------------------------------------------------------------------------

init_db()
poll_thread = threading.Thread(target=polling_loop, daemon=True)
poll_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    log.info("CertMailer starting on port %d", port)
    app.run(host="0.0.0.0", port=port)
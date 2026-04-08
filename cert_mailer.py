"""
CertMailer — Canvas webhook → PDF certificate → SendGrid email
---------------------------------------------------------------
Requirements:
    pip install flask pillow reportlab sendgrid requests

Environment variables (set these in Railway):
    CANVAS_URL          e.g. https://yourschool.instructure.com
    CANVAS_TOKEN        Canvas API token (generate in Canvas account settings)
    SENDGRID_API_KEY    SendGrid API key
    FROM_EMAIL          The email address you send FROM (verified in SendGrid)
    WEBHOOK_SECRET      A random string you set in Canvas webhook config
    CERT_IMAGE_PATH     Path to your certificate template image (PNG or JPG)
"""

import os
import io
import json
import hashlib
import hmac
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, request, jsonify
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import landscape, A4
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image as RLImage
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail, Attachment, FileContent, FileName, FileType, Disposition
)
import base64

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CANVAS_URL      = os.environ["CANVAS_URL"].rstrip("/")
CANVAS_TOKEN    = os.environ["CANVAS_TOKEN"]
SENDGRID_KEY    = os.environ["SENDGRID_API_KEY"]
FROM_EMAIL      = os.environ["FROM_EMAIL"]
WEBHOOK_SECRET  = os.environ.get("WEBHOOK_SECRET", "")
CERT_IMAGE_PATH = os.environ.get("CERT_IMAGE_PATH", "certificate_template.png")

# Name position on the certificate — adjust these to match your template.
# Values are percentages of the image width/height (0.0 – 1.0).
NAME_X_PCT  = 0.50   # horizontal center
NAME_Y_PCT  = 0.58   # vertical position
NAME_SIZE   = 72     # font size in pixels (tune to your template)
NAME_COLOR  = (30, 26, 22)   # dark ink RGB

DB_PATH = "cert_log.db"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database — tracks sent certificates so we never double-send
# ---------------------------------------------------------------------------

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS sent_certs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            course_id   TEXT NOT NULL,
            email       TEXT NOT NULL,
            sent_at     TEXT NOT NULL,
            UNIQUE(user_id, course_id)
        )
    """)
    con.commit()
    con.close()

def already_sent(user_id: str, course_id: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT 1 FROM sent_certs WHERE user_id=? AND course_id=?",
        (user_id, course_id)
    ).fetchone()
    con.close()
    return row is not None

def record_sent(user_id: str, course_id: str, email: str):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR IGNORE INTO sent_certs (user_id, course_id, email, sent_at) VALUES (?,?,?,?)",
        (user_id, course_id, email, datetime.utcnow().isoformat())
    )
    con.commit()
    con.close()

# ---------------------------------------------------------------------------
# Canvas API helpers
# ---------------------------------------------------------------------------

def canvas_get(path: str) -> dict:
    """Make an authenticated GET request to the Canvas API."""
    resp = requests.get(
        f"{CANVAS_URL}/api/v1/{path}",
        headers={"Authorization": f"Bearer {CANVAS_TOKEN}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()

def get_student_info(user_id: str) -> dict:
    """Return name and email for a Canvas user."""
    return canvas_get(f"users/{user_id}/profile")

def get_course_name(course_id: str) -> str:
    """Return the course name for a given course ID."""
    course = canvas_get(f"courses/{course_id}")
    return course.get("name", "your course")

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def load_font(size: int) -> ImageFont.FreeTypeFont:
    """
    Try to load Georgia. Falls back to the default PIL font if not found.
    On Railway (Linux) Georgia may not be installed — drop a georgia.ttf
    next to this script and it will be picked up automatically.
    """
    candidates = [
        "georgia.ttf",                          # same directory
        "/usr/share/fonts/truetype/msttcorefonts/Georgia.ttf",
        "/Library/Fonts/Georgia.ttf",           # macOS
        "C:/Windows/Fonts/georgia.ttf",         # Windows
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    log.warning("Georgia not found — using PIL default font. Drop georgia.ttf next to this script for best results.")
    return ImageFont.load_default()

def generate_cert_pdf(student_name: str) -> bytes:
    """
    Open the certificate template, stamp the student name, and return
    the finished certificate as PDF bytes.
    """
    # --- Draw name onto image ---
    img = Image.open(CERT_IMAGE_PATH).convert("RGB")
    draw = ImageDraw.Draw(img)
    font = load_font(NAME_SIZE)

    x = img.width  * NAME_X_PCT
    y = img.height * NAME_Y_PCT

    # Centre the text on (x, y)
    bbox = draw.textbbox((0, 0), student_name, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    draw.text((x - text_w / 2, y - text_h / 2), student_name, font=font, fill=NAME_COLOR)

    # --- Convert to PDF (landscape A4, image fills the page) ---
    page_w, page_h = landscape(A4)          # points (≈ 841 × 595)
    aspect = img.width / img.height
    fit_w  = page_w
    fit_h  = page_w / aspect
    if fit_h > page_h:
        fit_h = page_h
        fit_w = page_h * aspect
    x_off = (page_w - fit_w) / 2
    y_off = (page_h - fit_h) / 2

    # Save image to an in-memory buffer so ReportLab can read it
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
        onFirstPage=lambda canvas, doc: canvas.translate(x_off, y_off),
    )
    return pdf_buf.getvalue()

# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------

def send_cert_email(to_email: str, student_name: str, course_name: str, pdf_bytes: bytes):
    """Attach the PDF certificate and send it via SendGrid."""
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject=f"Your certificate for {course_name}",
        html_content=f"""
        <p>Hi {student_name},</p>
        <p>Congratulations on completing <strong>{course_name}</strong>!</p>
        <p>Your certificate is attached to this email as a PDF.</p>
        <p>Well done!</p>
        """,
    )

    encoded = base64.b64encode(pdf_bytes).decode()
    attachment = Attachment(
        FileContent(encoded),
        FileName(f"certificate_{student_name.replace(' ', '_')}.pdf"),
        FileType("application/pdf"),
        Disposition("attachment"),
    )
    message.attachment = attachment

    sg = SendGridAPIClient(SENDGRID_KEY)
    response = sg.send(message)
    log.info("SendGrid response: %s", response.status_code)

# ---------------------------------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------------------------------

def verify_signature(payload: bytes, signature: str) -> bool:
    """
    Canvas signs webhook payloads with HMAC-SHA256.
    The header is 'X-Canvas-Event-Signature' (check your Canvas docs —
    some versions use a different header name).
    """
    if not WEBHOOK_SECRET:
        return True   # skip verification if no secret configured
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")

@app.route("/webhook/canvas", methods=["POST"])
def canvas_webhook():
    payload   = request.get_data()
    signature = request.headers.get("X-Canvas-Event-Signature", "")

    if not verify_signature(payload, signature):
        log.warning("Invalid webhook signature — request rejected.")
        return jsonify({"error": "invalid signature"}), 403

    event = request.get_json(force=True)
    log.info("Canvas event received: %s", json.dumps(event)[:300])

    # Canvas sends course_progress events for completion.
    # The relevant event type is 'course_progress'.
    event_type = event.get("metadata", {}).get("event_name", "")
    if event_type != "course_progress":
        return jsonify({"status": "ignored", "reason": "not a course_progress event"}), 200

    body      = event.get("body", {})
    user_id   = str(body.get("user_id", ""))
    course_id = str(body.get("course_id", ""))
    completed = body.get("requirement_completed_count") == body.get("requirement_count")

    if not completed:
        return jsonify({"status": "ignored", "reason": "course not fully complete"}), 200

    if not user_id or not course_id:
        return jsonify({"error": "missing user_id or course_id"}), 400

    if already_sent(user_id, course_id):
        log.info("Certificate already sent to user %s for course %s — skipping.", user_id, course_id)
        return jsonify({"status": "already_sent"}), 200

    try:
        profile     = get_student_info(user_id)
        name        = profile.get("name", "Student")
        email       = profile.get("primary_email") or profile.get("login_id", "")
        course_name = get_course_name(course_id)

        if not email:
            log.error("No email found for user %s", user_id)
            return jsonify({"error": "no email for user"}), 500

        log.info("Generating certificate for %s (%s), course: %s", name, email, course_name)
        pdf_bytes = generate_cert_pdf(name)
        send_cert_email(email, name, course_name, pdf_bytes)
        record_sent(user_id, course_id, email)
        log.info("Certificate sent successfully to %s", email)

    except Exception as exc:
        log.exception("Failed to process certificate for user %s: %s", user_id, exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "sent", "email": email}), 200

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    log.info("CertMailer starting on port %d", port)
    app.run(host="0.0.0.0", port=port)

"""
CertMailer — Web version
-------------------------
Students enter their UCI NetID to check if they passed the final quiz
and download their certificate.

Environment variables:
    CANVAS_URL          e.g. https://canvas.eee.uci.edu
    CANVAS_TOKEN        Canvas API token
    CANVAS_COURSE_ID    e.g. 80782
    CANVAS_QUIZ_ID      e.g. 424718
    QUIZ_PASSING_SCORE  Minimum score to pass (e.g. 28 for 80% of 35pts)
    CERT_IMAGE_PATH     e.g. VCA_Cert_2026.png
"""

import io
import logging
import os
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template_string, request, send_file
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as rl_canvas

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CANVAS_URL         = os.environ["CANVAS_URL"].rstrip("/")
CANVAS_TOKEN       = os.environ["CANVAS_TOKEN"]
CANVAS_COURSE_ID   = os.environ["CANVAS_COURSE_ID"]
CANVAS_QUIZ_ID     = os.environ["CANVAS_QUIZ_ID"]
QUIZ_PASSING_SCORE = float(os.environ.get("QUIZ_PASSING_SCORE", "28"))
CERT_IMAGE_PATH    = os.environ.get("CERT_IMAGE_PATH", "VCA_Cert_2026.png")

NAME_X_PCT  = 0.50
NAME_Y_PCT  = 0.63
NAME_SIZE   = 80
NAME_COLOR  = (30, 26, 22)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Certificate Download</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f4f6f9;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0,0,0,.10);
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 440px;
      text-align: center;
    }
    .logo { font-size: 2.5rem; margin-bottom: .75rem; }
    h1 { font-size: 1.4rem; color: #1a1a2e; margin-bottom: .4rem; }
    p.sub { color: #666; font-size: .95rem; margin-bottom: 1.75rem; line-height: 1.5; }
    label { display: block; text-align: left; font-size: .85rem; font-weight: 600;
            color: #444; margin-bottom: .4rem; }
    .input-row {
      display: flex;
      gap: .5rem;
      margin-bottom: 1.25rem;
    }
    input[type=text] {
      flex: 1;
      padding: .65rem .9rem;
      border: 1.5px solid #d0d5dd;
      border-radius: 8px;
      font-size: 1rem;
      outline: none;
      transition: border-color .2s;
    }
    input[type=text]:focus { border-color: #0064a4; }
    .suffix {
      display: flex;
      align-items: center;
      padding: 0 .75rem;
      background: #f0f4f8;
      border: 1.5px solid #d0d5dd;
      border-radius: 8px;
      font-size: .95rem;
      color: #666;
      white-space: nowrap;
    }
    button {
      width: 100%;
      padding: .75rem;
      background: #0064a4;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background .2s;
    }
    button:hover { background: #004f83; }
    button:disabled { background: #8ab4cf; cursor: not-allowed; }
    .msg {
      margin-top: 1.25rem;
      padding: .85rem 1rem;
      border-radius: 8px;
      font-size: .95rem;
      display: none;
    }
    .msg.error   { background: #fff0f0; color: #c0392b; border: 1px solid #f5c6cb; }
    .msg.success { background: #edfaf1; color: #1a7f4b; border: 1px solid #b7e4c7; }
    .spinner {
      display: none;
      margin: .75rem auto 0;
      width: 24px; height: 24px;
      border: 3px solid #d0d5dd;
      border-top-color: #0064a4;
      border-radius: 50%;
      animation: spin .7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🎓</div>
    <h1>Course Certificate</h1>
    <p class="sub">Enter your UCI NetID below to check your quiz score and download your certificate.</p>

    <label for="netid">UCI NetID</label>
    <div class="input-row">
      <input type="text" id="netid" placeholder="e.g. jsmith" autocomplete="off" spellcheck="false">
      <div class="suffix">@uci.edu</div>
    </div>

    <button id="btn" onclick="checkCert()">Check &amp; Download</button>
    <div class="spinner" id="spinner"></div>
    <div class="msg" id="msg"></div>
  </div>

  <script>
    document.getElementById('netid').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') checkCert();
    });

    async function checkCert() {
      const netid = document.getElementById('netid').value.trim();
      const btn   = document.getElementById('btn');
      const msg   = document.getElementById('msg');
      const spin  = document.getElementById('spinner');

      msg.style.display = 'none';

      if (!netid) {
        showMsg('error', 'Please enter your NetID.');
        return;
      }

      btn.disabled = true;
      spin.style.display = 'block';

      try {
        const resp = await fetch('/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ netid })
        });

        if (resp.ok && resp.headers.get('content-type') === 'application/pdf') {
          const blob = await resp.blob();
          const url  = URL.createObjectURL(blob);
          const a    = document.createElement('a');
          a.href     = url;
          a.download = 'certificate.pdf';
          a.click();
          URL.revokeObjectURL(url);
          showMsg('success', 'Your certificate is downloading!');
        } else {
          const data = await resp.json();
          showMsg('error', data.error || 'Something went wrong. Please try again.');
        }
      } catch (err) {
        showMsg('error', 'Network error. Please try again.');
      } finally {
        btn.disabled = false;
        spin.style.display = 'none';
      }
    }

    function showMsg(type, text) {
      const msg = document.getElementById('msg');
      msg.className = 'msg ' + type;
      msg.textContent = text;
      msg.style.display = 'block';
    }
  </script>
</body>
</html>
"""

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

def find_student_submission(netid: str) -> dict | None:
    """
    Return the submission dict for the given NetID if they passed, else None.
    Matches login_id against 'netid' or 'netid@uci.edu'.
    """
    netid = netid.lower().strip()
    login_variants = {netid, f"{netid}@uci.edu"}

    raw = canvas_get_all(
        f"courses/{CANVAS_COURSE_ID}/quizzes/{CANVAS_QUIZ_ID}/submissions",
        params={"include[]": "user"}
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

    for sub in submissions:
        if not isinstance(sub, dict):
            continue

        uid_str  = str(sub.get("user_id", ""))
        user     = sub.get("user") or users_by_id.get(uid_str, {})
        login_id = user.get("login_id", "").lower()

        if login_id not in login_variants:
            continue

        score    = sub.get("kept_score")
        if score is None:
            score = sub.get("score", 0)
        workflow = sub.get("workflow_state", "")
        name     = user.get("name", "")

        log.info("Found submission for %s — score: %s, state: %s", login_id, score, workflow)

        if workflow in ("complete", "pending_review") and float(score) >= QUIZ_PASSING_SCORE:
            return {"name": name, "score": score}

        # Found them but didn't pass
        return {"name": name, "score": score, "failed": True}

    return None  # not found at all

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
    log.warning("No font file found — using PIL default. Add palatino.ttf or georgia.ttf to the repo.")
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
    c = rl_canvas.Canvas(pdf_buf, pagesize=landscape(A4))
    c.drawImage(ImageReader(img_buf), x_off, y_off, width=fit_w, height=fit_h)
    c.save()
    return pdf_buf.getvalue()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return render_template_string(PAGE)

@app.route("/check", methods=["POST"])
def check():
    data  = request.get_json(force=True, silent=True) or {}
    netid = (data.get("netid") or "").strip()

    if not netid:
        return jsonify({"error": "Please enter your NetID."}), 400

    log.info("Check request for NetID: %s", netid)

    try:
        result = find_student_submission(netid)
    except requests.HTTPError as e:
        log.exception("Canvas API error: %s", e)
        return jsonify({"error": "Could not reach Canvas. Please try again later."}), 502
    except Exception as e:
        log.exception("Unexpected error: %s", e)
        return jsonify({"error": "Something went wrong. Please try again."}), 500

    if result is None:
        return jsonify({"error": "No quiz submission found for that NetID. Make sure you've completed the quiz."}), 404

    if result.get("failed"):
        score = result["score"]
        return jsonify({"error": f"Your score ({score}) did not meet the passing threshold. Please retake the quiz."}), 403

    try:
        pdf_bytes = generate_cert_pdf(result["name"])
    except Exception as e:
        log.exception("PDF generation failed: %s", e)
        return jsonify({"error": "Certificate generation failed. Please contact your instructor."}), 500

    filename = f"certificate_{result['name'].replace(' ', '_')}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    log.info("CertMailer starting on port %d", port)
    app.run(host="0.0.0.0", port=port)

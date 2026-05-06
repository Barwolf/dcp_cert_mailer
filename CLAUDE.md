# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Flask web app where students enter their UCI NetID, the app checks if they passed a Canvas quiz, and lets them download a personalized PDF certificate. Deployed on Railway via gunicorn.

## Running locally

```bash
pip install -r requirements.txt
python cert_mailer.py          # starts Flask on port 8080
```

Required env vars: `CANVAS_URL`, `CANVAS_TOKEN`, `CANVAS_COURSE_ID`, `CANVAS_QUIZ_ID`. Optional: `QUIZ_PASSING_SCORE` (default 28), `CERT_IMAGE_PATH` (default `VCA_Cert_2026.png`).

## Endpoints

- `GET /` — HTML form for NetID entry
- `POST /check` — JSON body `{"netid": "jsmith"}`, returns PDF on success or JSON error
- `GET /health` — liveness check

## Architecture

Everything lives in a single file: `cert_mailer.py`.

**Flow:**
1. Student submits their NetID via the form (JS `fetch` POST to `/check`).
2. `find_student_submission(netid)` fetches all quiz submissions from Canvas and finds a match by `login_id` — handles both `netid` and `netid@uci.edu` formats.
3. If found and score >= `QUIZ_PASSING_SCORE`: generates a PDF cert and returns it for download.
4. If found but failed: returns a 403 with their score.
5. If not found: returns a 404.

**Canvas API notes:**
- `canvas_get_all` follows Link-header pagination (UCI Canvas style, not `?page=` params).
- The quiz submissions endpoint wraps results in `{"quiz_submissions": [...], "users": [...]}` — `find_student_submission` unwraps this.
- Student email/login is in `login_id`. Score uses `kept_score` first, falling back to `score`.
- Passing `workflow_state` values: `"complete"` or `"pending_review"`.

## Certificate image

`VCA_Cert_2026.png` is the certificate template. Name placement is controlled by `NAME_X_PCT`, `NAME_Y_PCT`, and `NAME_SIZE` constants at the top of `cert_mailer.py`. Font lookup tries `palatino.ttf` then `georgia.ttf` (committed to repo).

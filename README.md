# CampusFix

Complaint management for Shobhit University (Student / Staff / Admin). Flask + MySQL (Aiven) + Brevo email.

## Run locally
```
python -m venv venv && venv\Scripts\activate      # Windows
pip install -r requirements.txt
copy .env.example .env                             # then fill it in
python db.py                                       # creates / upgrades the tables
python db.py create-admin                          # first admin
flask --app app run --debug
```

## Deploy on Render
| Setting | Value |
|---|---|
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn app:app -c gunicorn.conf.py` |
| Health Check Path | `/healthz` |
| Environment | everything in `.env.example` (real values) |

* `/healthz` = process is alive (no database). `/readyz` = database reachable - use it for uptime monitors.
* In the Aiven allow-list keep only Render's outbound IP ranges (not `0.0.0.0/0`).
* Free Render instances sleep after inactivity (first request takes ~30-60 s). Use a paid instance for real traffic.

## Scaling
OTPs, reset tokens, "email verified" tickets and the OTP / email-budget counters live in the database
(tables `auth_state` and `counters`), so they survive restarts and you may raise `GUNICORN_WORKERS` to 2 or more.
That only helps on an instance with 1+ CPU; on a small instance extra workers just share the same little CPU.

Still per worker (not shared): per-IP rate limits and login lock-outs (with N workers the real limit is N x the
number shown in the code) and the password-hash gate (`MAX_PARALLEL_HASH`).

## Testing
`tests/TEST_PLAN.md` has the full test plan and the latest report.
* `python tests/smoke_live.py --base <url> --student-id <test roll> --student-pass <pw>` - 40+ automatic checks on the live site.
* `python tests/loadtest.py --base <url> --login-id <test roll> --password <pw> --users 20 --duration 30` - load test (nothing to install).

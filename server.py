from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import socket
import sqlite3
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("VIARKA_SCORE_DB", str(ROOT / "viarka_score.db")))
HOST = os.environ.get("VIARKA_SCORE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", os.environ.get("VIARKA_SCORE_PORT", "8765")))
PAIR_TTL_SECONDS = 12 * 60 * 60


def database() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize_database() -> None:
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pairing_codes (
                token TEXT PRIMARY KEY,
                terminal_id TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id),
                session_key TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'waiting',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                terminal_id TEXT NOT NULL,
                score INTEGER NOT NULL,
                max_multiplier REAL NOT NULL,
                near_misses INTEGER NOT NULL,
                collisions INTEGER NOT NULL,
                duration REAL NOT NULL,
                car_name TEXT NOT NULL,
                track_name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS runs_user_score ON runs(user_id, score DESC);
            CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at DESC);
            """
        )


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def password_valid(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def lan_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        value = sock.getsockname()[0]
        sock.close()
        return value
    except OSError:
        return "127.0.0.1"


STYLE = """
:root{color-scheme:dark;font-family:Inter,Segoe UI,Arial,sans-serif;background:#060b13;color:#eff7ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 25% 10%,#0e3158 0,#07111f 34%,#03070c 100%)}
.wrap{width:min(920px,calc(100% - 32px));margin:40px auto}.card{background:rgba(8,18,31,.82);border:1px solid rgba(62,157,255,.25);border-radius:22px;padding:26px;box-shadow:0 24px 80px rgba(0,0,0,.45);backdrop-filter:blur(18px)}
h1,h2{margin:0 0 12px}.brand{color:#29a3ff;letter-spacing:.12em;font-size:13px;font-weight:800}.muted{color:#8da3b8}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:720px){.grid{grid-template-columns:1fr}}
label{display:block;margin:12px 0 6px;color:#a9bad0}input{width:100%;padding:13px 14px;border-radius:11px;border:1px solid #27445f;background:#07111d;color:white;font-size:16px}
button{margin-top:18px;width:100%;padding:14px;border:0;border-radius:12px;background:linear-gradient(90deg,#087cff,#20b8ff);color:white;font-weight:800;font-size:15px;cursor:pointer}.error{color:#ff7f91}.ok{color:#67e8aa}
table{width:100%;border-collapse:collapse;margin-top:18px}th,td{text-align:left;padding:12px;border-bottom:1px solid rgba(255,255,255,.08)}th{color:#7da4c8;font-size:12px;text-transform:uppercase}.score{color:#45b5ff;font-weight:800}
"""


def page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body><main class='wrap'>{body}</main></body></html>"
    ).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "VIARKAScore/0.1"

    def log_message(self, fmt: str, *args) -> None:
        print(time.strftime("%H:%M:%S"), self.client_address[0], fmt % args)

    def send_bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value: dict | list, status: int = 200) -> None:
        self.send_bytes(json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def body(self) -> bytes:
        length = min(int(self.headers.get("Content-Length", "0") or 0), 1_000_000)
        return self.rfile.read(length)

    def json_body(self) -> dict:
        try:
            return json.loads(self.body().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def form_body(self) -> dict[str, str]:
        parsed = parse_qs(self.body().decode("utf-8", "replace"), keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.leaderboard_page()
        elif parsed.path == "/pair":
            token = parse_qs(parsed.query).get("token", [""])[0]
            self.pair_page(token)
        elif parsed.path.startswith("/api/pairing/"):
            self.pair_status(parsed.path.rsplit("/", 1)[-1])
        elif parsed.path == "/api/leaderboard":
            self.leaderboard_json()
        elif parsed.path == "/health":
            self.send_json({"ok": True, "service": "VIARKA Score"})
        else:
            self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/pairing":
            self.create_pairing()
        elif parsed.path == "/pair":
            self.complete_pairing(self.form_body())
        elif parsed.path == "/api/runs":
            self.save_run(self.json_body())
        else:
            self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def create_pairing(self) -> None:
        data = self.json_body()
        terminal_id = str(data.get("terminal_id", "unknown"))[:80]
        now = int(time.time())
        token = secrets.token_urlsafe(18)
        with database() as db:
            db.execute("DELETE FROM pairing_codes WHERE expires_at < ?", (now,))
            db.execute(
                "INSERT INTO pairing_codes(token,terminal_id,created_at,expires_at) VALUES(?,?,?,?)",
                (token, terminal_id, now, now + PAIR_TTL_SECONDS),
            )
        public_url = os.environ.get("VIARKA_SCORE_PUBLIC_URL", "").rstrip("/")
        if not public_url:
            forwarded_proto = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0].strip()
            forwarded_host = self.headers.get("X-Forwarded-Host", self.headers.get("Host", "")).split(",", 1)[0].strip()
            public_url = f"{forwarded_proto}://{forwarded_host}" if forwarded_host else f"http://{lan_ip()}:{PORT}"
        self.send_json({"token": token, "pair_url": f"{public_url}/pair?token={token}", "expires_in": PAIR_TTL_SECONDS})

    def pair_status(self, token: str) -> None:
        with database() as db:
            row = db.execute(
                """SELECT p.status,p.session_key,p.expires_at,u.display_name,
                COALESCE(MAX(r.score),0) best_score
                FROM pairing_codes p LEFT JOIN users u ON u.id=p.user_id
                LEFT JOIN runs r ON r.user_id=u.id WHERE p.token=? GROUP BY p.token""",
                (token,),
            ).fetchone()
        if not row or row["expires_at"] < int(time.time()):
            self.send_json({"status": "expired"}, HTTPStatus.GONE)
            return
        result = {"status": row["status"]}
        if row["status"] == "paired":
            result.update(session_key=row["session_key"], display_name=row["display_name"], best_score=row["best_score"])
        self.send_json(result)

    def pair_page(self, token: str, message: str = "", error: bool = False) -> None:
        with database() as db:
            pairing = db.execute("SELECT status,expires_at FROM pairing_codes WHERE token=?", (token,)).fetchone()
        if not pairing or pairing["expires_at"] < int(time.time()):
            self.send_bytes(page("Код истёк", "<section class='card'><h1>QR-код истёк</h1><p class='muted'>Получите новый код в игре.</p></section>"), "text/html; charset=utf-8", 410)
            return
        if pairing["status"] == "paired":
            self.send_bytes(page("Готово", "<section class='card'><div class='brand'>ВИАРКА SCORE</div><h1 class='ok'>Аккаунт подключён</h1><p>Можно вернуться к симулятору.</p></section>"), "text/html; charset=utf-8")
            return
        notice = f"<p class='{'error' if error else 'ok'}'>{html.escape(message)}</p>" if message else ""
        body = f"""
        <section class='card'><div class='brand'>ВИАРКА SCORE</div><h1>Подключить игрока</h1>
        <p class='muted'>Создайте новый аккаунт или войдите в существующий. Steam не используется.</p>{notice}
        <div class='grid'>
          <form method='post' action='/pair'><h2>Регистрация</h2><input type='hidden' name='token' value='{html.escape(token)}'><input type='hidden' name='mode' value='register'>
            <label>Имя в рейтинге</label><input name='display_name' maxlength='28' required>
            <label>Почта</label><input name='email' type='email' maxlength='160' required>
            <label>Пароль</label><input name='password' type='password' minlength='8' maxlength='128' required>
            <button>Создать и подключить</button></form>
          <form method='post' action='/pair'><h2>Уже есть аккаунт</h2><input type='hidden' name='token' value='{html.escape(token)}'><input type='hidden' name='mode' value='login'>
            <label>Почта</label><input name='email' type='email' required>
            <label>Пароль</label><input name='password' type='password' required>
            <button>Войти и подключить</button></form>
        </div></section>"""
        self.send_bytes(page("Подключение игрока", body), "text/html; charset=utf-8")

    def complete_pairing(self, form: dict[str, str]) -> None:
        token = form.get("token", "")
        email = form.get("email", "").strip().lower()
        password = form.get("password", "")
        mode = form.get("mode", "login")
        if not email or len(password) < 8:
            self.pair_page(token, "Проверьте почту и пароль: минимум 8 символов.", True)
            return
        now = int(time.time())
        try:
            with database() as db:
                pair = db.execute("SELECT * FROM pairing_codes WHERE token=?", (token,)).fetchone()
                if not pair or pair["status"] != "waiting" or pair["expires_at"] < now:
                    self.pair_page(token, "Код недействителен или уже использован.", True)
                    return
                if mode == "register":
                    name = form.get("display_name", "").strip()[:28]
                    if len(name) < 2:
                        self.pair_page(token, "Введите отображаемое имя.", True)
                        return
                    cursor = db.execute(
                        "INSERT INTO users(email,display_name,password_hash,created_at) VALUES(?,?,?,?)",
                        (email, name, password_hash(password), now),
                    )
                    user_id = cursor.lastrowid
                else:
                    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                    if not user or not password_valid(password, user["password_hash"]):
                        self.pair_page(token, "Неверная почта или пароль.", True)
                        return
                    user_id = user["id"]
                session_key = secrets.token_urlsafe(32)
                db.execute(
                    "UPDATE pairing_codes SET user_id=?,session_key=?,status='paired' WHERE token=?",
                    (user_id, session_key, token),
                )
        except sqlite3.IntegrityError:
            self.pair_page(token, "Аккаунт с такой почтой уже существует.", True)
            return
        self.pair_page(token)

    def save_run(self, data: dict) -> None:
        session_key = str(data.get("session_key", ""))
        with database() as db:
            pair = db.execute(
                "SELECT user_id,terminal_id FROM pairing_codes WHERE session_key=? AND status='paired'",
                (session_key,),
            ).fetchone()
            if not pair:
                self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            score = max(0, min(int(data.get("score", 0)), 2_000_000_000))
            values = (
                pair["user_id"], pair["terminal_id"], score,
                max(1.0, min(float(data.get("max_multiplier", 1)), 100.0)),
                max(0, int(data.get("near_misses", 0))),
                max(0, int(data.get("collisions", 0))),
                max(0.0, min(float(data.get("duration", 0)), 86400.0)),
                str(data.get("car_name", "Unknown"))[:100],
                str(data.get("track_name", "Unknown"))[:100], int(time.time()),
            )
            db.execute(
                """INSERT INTO runs(user_id,terminal_id,score,max_multiplier,near_misses,collisions,duration,car_name,track_name,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)""", values,
            )
            best = db.execute("SELECT MAX(score) best FROM runs WHERE user_id=?", (pair["user_id"],)).fetchone()["best"]
        self.send_json({"ok": True, "best_score": best, "new_record": score >= best})

    def leaderboard_rows(self) -> list[sqlite3.Row]:
        with database() as db:
            return db.execute(
                """SELECT u.display_name,MAX(r.score) score,COUNT(r.id) runs
                FROM users u JOIN runs r ON r.user_id=u.id
                GROUP BY u.id ORDER BY score DESC, MIN(r.created_at) ASC LIMIT 100"""
            ).fetchall()

    def leaderboard_json(self) -> None:
        self.send_json([dict(rank=i + 1, **dict(row)) for i, row in enumerate(self.leaderboard_rows())])

    def leaderboard_page(self) -> None:
        rows = self.leaderboard_rows()
        table = "".join(
            f"<tr><td>{i+1}</td><td>{html.escape(row['display_name'])}</td><td class='score'>{row['score']:,}</td><td>{row['runs']}</td></tr>"
            for i, row in enumerate(rows)
        ) or "<tr><td colspan='4' class='muted'>Пока нет завершённых попыток</td></tr>"
        body = f"<section class='card'><div class='brand'>ВИАРКА SCORE</div><h1>Таблица лидеров</h1><p class='muted'>Лучший результат каждого игрока</p><table><thead><tr><th>#</th><th>Игрок</th><th>Рекорд</th><th>Попытки</th></tr></thead><tbody>{table}</tbody></table></section>"
        self.send_bytes(page("ВИАРКА — рейтинг", body), "text/html; charset=utf-8")


if __name__ == "__main__":
    initialize_database()
    print(f"VIARKA Score server: http://127.0.0.1:{PORT}")
    print(f"Leaderboard on local network: http://{lan_ip()}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

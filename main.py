import http.server
import socketserver
import os
import cgi
import zipfile
import datetime
import secrets
import json
import io
import base64
import html
from urllib.parse import quote, unquote, parse_qs, unquote_plus, urlparse

import qrcode


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")
SESSION_FILE = os.path.join(BASE_DIR, "sessions.json")

MAX_SIZE = 4 * 1024 * 1024 * 1024  # 4 ГБ
SESSION_DURATION = 100 * 60         # 1 ч 40 мин
QR_PENDING_DURATION = 60            # 60 секунд

UPLOAD_DIR = os.getcwd()
UPLOAD_FOLDER = os.path.join(UPLOAD_DIR, "upload")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sessions = {}
pending_logins = {}


def load_env(path):
    data = {}
    if not os.path.exists(path):
        return data

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    return data


env = load_env(ENV_FILE)

USER_NAME = env.get("USER_NAME", "sharefiles")
USER_PASS = env.get("USER_PASS", "123456")

ADMIN_NAME = env.get("ADMIN_NAME", "admin")
ADMIN_PASS = env.get("ADMIN_PASS", "admin123")

PORT = int(env.get("PORT", "6574"))


def load_sessions():
    global sessions
    if not os.path.exists(SESSION_FILE):
        sessions = {}
        return

    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
            sessions = {
                k: {
                    "user": v["user"],
                    "role": v["role"],
                    "expires": v.get("expires"),
                    "permanent": v.get("permanent", False)
                }
                for k, v in raw.items()
            }
    except Exception:
        sessions = {}


def save_sessions():
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(sessions, f, ensure_ascii=False, indent=2)


def cleanup_sessions():
    now_ts = datetime.datetime.now().timestamp()
    expired = [
        sid for sid, data in sessions.items()
        if not data.get("permanent", False)
        and data.get("expires") is not None
        and data["expires"] <= now_ts
    ]
    for sid in expired:
        del sessions[sid]
    if expired:
        save_sessions()


def cleanup_pending():
    now_ts = datetime.datetime.now().timestamp()
    expired = [
        token for token, data in pending_logins.items()
        if data["expires"] <= now_ts or data.get("used", False)
    ]
    for token in expired:
        del pending_logins[token]


def create_session(username, role):
    session_id = secrets.token_hex(16)

    if role == "admin":
        sessions[session_id] = {
            "user": username,
            "role": role,
            "expires": None,
            "permanent": True
        }
    else:
        sessions[session_id] = {
            "user": username,
            "role": role,
            "expires": datetime.datetime.now().timestamp() + SESSION_DURATION,
            "permanent": False
        }

    save_sessions()
    return session_id


def get_role_for_user(username, password):
    if username == USER_NAME and password == USER_PASS:
        return "user"
    if username == ADMIN_NAME and password == ADMIN_PASS:
        return "admin"
    return None


def make_qr_base64(data):
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def esc(value):
    return html.escape(str(value), quote=True)


def build_cookie_header(session_id, max_age=None):
    parts = [
        f"session={session_id}",
        "HttpOnly",
        "Path=/",
        "SameSite=Lax"
    ]

    # Secure включай, если реально сервер работает через HTTPS
    # parts.append("Secure")

    if max_age is not None:
        parts.append(f"Max-Age={max_age}")

    return "; ".join(parts)


load_sessions()


class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def render_html(self, body, title="Файловый сервер"):
        html_doc = f"""
        <html>
        <head>
            <meta charset="utf-8">
            <title>{esc(title)}</title>
            <style>
                body {{
                    background-color: #111;
                    color: #eee;
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }}
                a {{
                    color: #0af;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
                ul {{
                    list-style-type: none;
                    padding-left: 0;
                }}
                input, button {{
                    background: #1e1e1e;
                    color: #eee;
                    border: 1px solid #444;
                    padding: 8px 10px;
                    margin: 4px 0;
                }}
                button {{
                    cursor: pointer;
                }}
                #dropzone {{
                    width: 700px;
                    height: 320px;
                    border: 2px dashed #aaa;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 20px;
                    margin-bottom: 20px;
                    color: #aaa;
                    font-weight: bold;
                }}
                .box {{
                    border: 1px solid #333;
                    padding: 16px;
                    margin: 12px 0;
                    background: #161616;
                }}
                .ok {{ color: #7CFC98; }}
                .bad {{ color: #ff7b7b; }}
                .warn {{ color: #ffd166; }}
            </style>
        </head>
        <body>
        {body}
        </body>
        </html>
        """
        return html_doc.encode("utf-8")

    def send_html(self, body, status=200, title="Файловый сервер"):
        self.send_response(status)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.render_html(body, title))

    def send_json(self, text, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def get_session_id_from_cookie(self):
        cleanup_sessions()

        cookie = self.headers.get("Cookie")
        if not cookie:
            return None

        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                session_id = part.split("=", 1)[1]
                data = sessions.get(session_id)
                if not data:
                    return None

                if data.get("permanent", False):
                    return session_id

                now_ts = datetime.datetime.now().timestamp()
                if data.get("expires") is not None and data["expires"] > now_ts:
                    data["expires"] = now_ts + SESSION_DURATION
                    save_sessions()
                    return session_id

        return None

    def get_session(self):
        sid = self.get_session_id_from_cookie()
        if not sid:
            return None
        return sessions.get(sid)

    def require_session(self):
        sess = self.get_session()
        if not sess:
            self.redirect("/login")
            return None
        return sess

    def require_admin(self):
        sess = self.get_session()
        if not sess:
            self.redirect("/login")
            return None
        if sess.get("role") != "admin":
            self.send_html("<h2 class='bad'>Доступ только для администратора</h2>", 403)
            return None
        return sess

    def build_external_base(self):
        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        return f"http://{host}"

    def show_login_page(self, message=""):
        msg = f"<div class='box warn'>{esc(message)}</div>" if message else ""
        body = f"""
        <h2>Авторизация</h2>
        {msg}
        <form method="POST" action="/login">
            <div>Логин:</div>
            <input name="user" autocomplete="username">
            <div>Пароль:</div>
            <input type="password" name="pass" autocomplete="current-password">
            <br>
            <input type="submit" value="Войти">
        </form>

        <div class="box">
            <a href="/qr-login">Войти через QR с подтверждением админа</a>
        </div>
        """
        self.send_html(body, title="Вход")

    def do_GET(self):
        cleanup_pending()

        parsed = urlparse(self.path)
        path_only = parsed.path
        query = parse_qs(parsed.query)

        if path_only == "/login":
            sess = self.get_session()
            if sess:
                self.redirect("/")
                return
            self.show_login_page()
            return

        if path_only == "/logout":
            sid = self.get_session_id_from_cookie()
            if sid and sid in sessions:
                del sessions[sid]
                save_sessions()

            self.send_response(302)
            self.send_header("Set-Cookie", build_cookie_header("", max_age=0))
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path_only == "/qr-login":
            if self.get_session():
                self.redirect("/")
                return

            token = secrets.token_hex(16)
            pending_logins[token] = {
                "expires": datetime.datetime.now().timestamp() + QR_PENDING_DURATION,
                "approved": False,
                "denied": False,
                "used": False,
                "approved_by": None,
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": self.client_address[0],
                "user_agent": self.headers.get("User-Agent", "")
            }

            qr_url = f"{self.build_external_base()}/approve-login?token={token}"
            qr_img = make_qr_base64(qr_url)

            body = f"""
            <h2>QR-вход</h2>
            <div class="box">
                Открой эту страницу на ПК и сканируй QR телефоном, где уже есть админ-доступ.
            </div>

            <div class="box">
                <img src="data:image/png;base64,{qr_img}" alt="QR">
            </div>

            <div class="box">
                Токен живёт <b>60 секунд</b>.<br>
                После подтверждения этой вкладке будет выдана сессия.
            </div>

            <div id="status" class="box warn">Ожидание подтверждения админом...</div>

            <script>
            async function poll() {{
                try {{
                    const r = await fetch("/poll-login?token={token}");
                    const data = await r.json();

                    if (data.status === "approved") {{
                        document.getElementById("status").innerHTML = "Подтверждено. Выполняю вход...";
                        window.location.href = "/complete-login?token={token}";
                        return;
                    }}

                    if (data.status === "denied") {{
                        document.getElementById("status").innerHTML = "Запрос отклонён админом.";
                        return;
                    }}

                    if (data.status === "expired") {{
                        document.getElementById("status").innerHTML = "QR истёк. Обнови страницу.";
                        return;
                    }}

                    setTimeout(poll, 2000);
                }} catch (e) {{
                    document.getElementById("status").innerHTML = "Ошибка проверки статуса.";
                }}
            }}
            poll();
            </script>

            <br><a href="/login">Назад</a>
            """
            self.send_html(body, title="QR-вход")
            return

        if path_only == "/poll-login":
            token = query.get("token", [""])[0]
            item = pending_logins.get(token)
            if not item:
                self.send_json('{"status":"expired"}')
                return

            now_ts = datetime.datetime.now().timestamp()
            if item["expires"] <= now_ts:
                self.send_json('{"status":"expired"}')
                return

            if item["denied"]:
                self.send_json('{"status":"denied"}')
                return

            if item["approved"]:
                self.send_json('{"status":"approved"}')
                return

            self.send_json('{"status":"pending"}')
            return

        if path_only == "/complete-login":
            token = query.get("token", [""])[0]
            item = pending_logins.get(token)
            if not item:
                self.send_html("<h2 class='bad'>Токен недействителен или истёк</h2>", 403)
                return

            now_ts = datetime.datetime.now().timestamp()
            if item["expires"] <= now_ts or item["denied"] or item["used"] or not item["approved"]:
                self.send_html("<h2 class='bad'>Нельзя завершить вход</h2>", 403)
                return

            session_id = create_session(USER_NAME, "user")
            item["used"] = True

            self.send_response(302)
            self.send_header("Set-Cookie", build_cookie_header(session_id))
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path_only == "/approve-login":
            token = query.get("token", [""])[0]
            item = pending_logins.get(token)
            if not item:
                self.send_html("<h2 class='bad'>QR недействителен или истёк</h2>", 403)
                return

            now_ts = datetime.datetime.now().timestamp()
            if item["expires"] <= now_ts:
                self.send_html("<h2 class='bad'>QR истёк</h2>", 403)
                return

            admin = self.require_admin()
            if not admin:
                return

            status_text = "Ожидает решения"
            if item["approved"]:
                status_text = "Уже подтверждено"
            elif item["denied"]:
                status_text = "Уже отклонено"

            body = f"""
            <h2>Подтверждение QR-входа</h2>

            <div class="box">
                <b>Статус:</b> {esc(status_text)}<br>
                <b>Создан:</b> {esc(item["created_at"])}<br>
                <b>IP:</b> {esc(item["client_ip"])}<br>
                <b>User-Agent:</b> {esc(item["user_agent"][:300])}
            </div>

            <form method="POST" action="/approve-login">
                <input type="hidden" name="token" value="{esc(token)}">
                <button type="submit" name="action" value="approve">Разрешить вход</button>
                <button type="submit" name="action" value="deny">Отклонить</button>
            </form>

            <br><a href="/">На главную</a>
            """
            self.send_html(body, title="Подтверждение входа")
            return

        sess = self.require_session()
        if not sess:
            return

        if path_only == "/upload":
            body = """
            <h2>Загрузка файла</h2>
            <div id="dropzone">Перетащи файлы сюда</div>

            <form id="form" method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit" value="Загрузить">
            </form>

            <script>
            const dropzone = document.getElementById('dropzone');
            dropzone.ondragover = e => {
                e.preventDefault();
                dropzone.style.borderColor = 'green';
            };
            dropzone.ondragleave = e => {
                dropzone.style.borderColor = '#aaa';
            };
            dropzone.ondrop = e => {
                e.preventDefault();
                dropzone.style.borderColor = '#aaa';
                let file = e.dataTransfer.files[0];
                let formData = new FormData();
                formData.append("file", file);
                fetch("/upload", { method: "POST", body: formData }).then(() => {
                    alert("Файл загружен!");
                    window.location.href = "/";
                });
            };
            </script>

            <br><a href="/">Назад</a>
            """
            self.send_html(body, title="Загрузка")
            return

        real_path = os.path.normpath(os.path.join(UPLOAD_DIR, unquote(path_only.lstrip("/"))))
        if not real_path.startswith(os.path.abspath(UPLOAD_DIR)):
            self.send_error(403)
            return

        if os.path.isdir(real_path):
            files = [f for f in os.listdir(real_path) if f != "upload"]

            body = f"""
            <a href="/logout">Выйти</a>
            <h2>Папка: {esc(path_only)}</h2>
            <ul>
            """

            if path_only != "/":
                parent = "/".join(path_only.rstrip("/").split("/")[:-1])
                if parent == "":
                    parent = "/"
                body += f'<li><a href="{esc(parent)}">⬅️ Назад</a></li>'

            for f in files:
                full = os.path.join(real_path, f)
                url_name = quote(f)
                safe_name = esc(f)
                safe_href = f"{path_only.rstrip('/')}/{url_name}" if path_only.rstrip("/") else f"/{url_name}"

                if os.path.isdir(full):
                    body += f'<li>📁 <a href="{safe_href}/">{safe_name}/</a></li>'
                else:
                    body += f'<li>📄 <a href="{safe_href}">{safe_name}</a></li>'

            body += "</ul>"

            if path_only == "/":
                body += "<br><a href='/upload'>Загрузить файл</a>"

            self.send_html(body)
            return

        if os.path.isfile(real_path):
            filename = os.path.basename(real_path)
            filename_quoted = quote(filename)
            self.send_response(200)
            self.send_header(
                "Content-Disposition",
                f"attachment; filename*=UTF-8''{filename_quoted}"
            )
            self.end_headers()
            with open(real_path, "rb") as f:
                self.wfile.write(f.read())
            return

        self.send_error(404)

    def do_POST(self):
        cleanup_pending()

        parsed = urlparse(self.path)
        path_only = parsed.path

        if path_only == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            params = parse_qs(body)

            user = unquote_plus(params.get("user", [""])[0])
            password = unquote_plus(params.get("pass", [""])[0])

            role = get_role_for_user(user, password)
            if role:
                session_id = create_session(user, role)
                self.send_response(302)
                self.send_header("Set-Cookie", build_cookie_header(session_id))
                self.send_header("Location", "/")
                self.end_headers()
                return

            self.show_login_page("Неверный логин или пароль")
            return

        if path_only == "/approve-login":
            admin = self.require_admin()
            if not admin:
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            params = parse_qs(body)

            token = params.get("token", [""])[0]
            action = params.get("action", [""])[0]

            item = pending_logins.get(token)
            if not item:
                self.send_html("<h2 class='bad'>Токен недействителен</h2>", 403)
                return

            now_ts = datetime.datetime.now().timestamp()
            if item["expires"] <= now_ts:
                self.send_html("<h2 class='bad'>Токен истёк</h2>", 403)
                return

            if action == "approve":
                item["approved"] = True
                item["denied"] = False
                item["approved_by"] = admin["user"]
                self.send_html("<h2 class='ok'>Вход разрешён</h2><a href='/'>На главную</a>")
                return

            if action == "deny":
                item["denied"] = True
                item["approved"] = False
                item["approved_by"] = admin["user"]
                self.send_html("<h2 class='bad'>Вход отклонён</h2><a href='/'>На главную</a>")
                return

            self.send_html("<h2 class='bad'>Неизвестное действие</h2>", 400)
            return

        sess = self.require_session()
        if not sess:
            return

        if path_only == "/upload":
            ctype, pdict = cgi.parse_header(self.headers.get("content-type"))
            if ctype == "multipart/form-data":
                pdict["boundary"] = bytes(pdict["boundary"], "utf-8")
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={"REQUEST_METHOD": "POST"}
                )

                file_item = form["file"]
                if file_item.filename:
                    file_item.file.seek(0, os.SEEK_END)
                    size = file_item.file.tell()
                    file_item.file.seek(0)

                    if size > MAX_SIZE:
                        self.send_html("Файл превышает лимит 4 ГБ.", 413)
                        return

                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    zip_name = f"{timestamp}.zip"
                    zip_path = os.path.join(UPLOAD_FOLDER, zip_name)

                    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                        zipf.writestr(os.path.basename(file_item.filename), file_item.file.read())

                    self.send_html("Файл успешно загружен!")
                    return

            self.send_error(400)
            return

        self.send_error(400)

    def do_HEAD(self):
        return self.do_GET()

    def do_PUT(self):
        return self.do_POST()


with socketserver.TCPServer(("", PORT), AuthHandler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
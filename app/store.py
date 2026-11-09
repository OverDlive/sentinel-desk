import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from .domain import PROVIDERS, SEARCH_PROVIDERS, SEVERITIES, STATUSES, compile_rules, digest, now, validate_target, web_finding, search_identity
from .vault import seal, unseal


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "sentinel.sqlite3"
        with self.db() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, data TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS providers (id TEXT PRIMARY KEY, secret TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 0, daily_limit INTEGER NOT NULL DEFAULT 100, pages INTEGER NOT NULL DEFAULT 1,
                organization_id TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                provider TEXT NOT NULL, kind TEXT NOT NULL, query TEXT NOT NULL, label TEXT NOT NULL, source_row TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, last_run TEXT);
            CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL,
                trigger TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, new_count INTEGER NOT NULL DEFAULT 0,
                changed_count INTEGER NOT NULL DEFAULT 0, result_count INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS run_steps (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
                provider TEXT NOT NULL, target_id INTEGER, rule_id INTEGER, query TEXT NOT NULL, status TEXT NOT NULL,
                result_count INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, mode TEXT NOT NULL,
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, identity TEXT NOT NULL,
                title TEXT NOT NULL, url TEXT NOT NULL, asset TEXT NOT NULL, summary TEXT NOT NULL, kind TEXT NOT NULL,
                severity TEXT NOT NULL, confidence TEXT NOT NULL, reason TEXT NOT NULL, cves TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observed_at TEXT, change_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'new', owner TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
                UNIQUE(mode,target_id,identity));
            CREATE TABLE IF NOT EXISTS sightings (id INTEGER PRIMARY KEY,
                finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE, provider TEXT NOT NULL,
                rule_id INTEGER, query TEXT NOT NULL, content_hash TEXT NOT NULL, evidence TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observed_at TEXT, count INTEGER NOT NULL DEFAULT 1,
                UNIQUE(finding_id,provider,query,content_hash));
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY,
                finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE, created_at TEXT NOT NULL,
                message TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS findings_mode_seen ON findings(mode,last_seen);
            CREATE INDEX IF NOT EXISTS requests_provider ON requests(provider,created_at);
            CREATE TABLE IF NOT EXISTS run_findings (
                run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                is_new INTEGER NOT NULL DEFAULT 0, changed INTEGER NOT NULL DEFAULT 0,
                snapshot TEXT NOT NULL DEFAULT '{}', sources TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY(run_id,finding_id));
            CREATE TABLE IF NOT EXISTS censys_host_cache (account TEXT NOT NULL, ip TEXT NOT NULL,
                fetched_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(account,ip));
            CREATE TABLE IF NOT EXISTS censys_lookup_cursors (
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                cidr TEXT NOT NULL, position TEXT NOT NULL DEFAULT '0', PRIMARY KEY(target_id,cidr));
            """)
            columns = {r["name"] for r in db.execute("PRAGMA table_info(providers)")}
            if "result_index" not in {r["name"] for r in db.execute("PRAGMA table_info(runs)")}:
                db.execute("ALTER TABLE runs ADD COLUMN result_index TEXT NOT NULL DEFAULT 'legacy'")
            if "search_backend" not in columns:
                db.execute("ALTER TABLE providers ADD COLUMN search_backend TEXT NOT NULL DEFAULT 'serpapi'")
                # Keep existing paid integrations; keyless installations start with HTML.
                db.execute("UPDATE providers SET search_backend='direct_html' WHERE id IN ('google','baidu','zoneh','xssed') AND secret=''")
            if "censys_mode" not in columns:
                db.execute("ALTER TABLE providers ADD COLUMN censys_mode TEXT NOT NULL DEFAULT 'lookup'")
                # Existing configured accounts retain their search entitlement/settings.
                db.execute("UPDATE providers SET censys_mode='search' WHERE id='censys' AND secret<>''")
            if "lookup_limit" not in columns:
                db.execute("ALTER TABLE providers ADD COLUMN lookup_limit INTEGER NOT NULL DEFAULT 10")
            if "monthly_limit" not in columns:
                db.execute("ALTER TABLE providers ADD COLUMN monthly_limit INTEGER NOT NULL DEFAULT 100")
            request_columns = {r["name"] for r in db.execute("PRAGMA table_info(requests)")}
            if "operation" not in request_columns:
                db.execute("ALTER TABLE requests ADD COLUMN operation TEXT NOT NULL DEFAULT ''")
            defaults = dict(schedule_enabled=False, interval_minutes=360, max_queries_per_run=40, last_scheduled_at=None)
            db.execute("INSERT OR IGNORE INTO settings VALUES (1,?)", (json.dumps(defaults),))
            for p in PROVIDERS:
                db.execute("INSERT OR IGNORE INTO providers(id,search_backend) VALUES (?,?)", (p["id"], "direct_html" if p["id"] in SEARCH_PROVIDERS else "serpapi"))
            settings = json.loads(db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0])
            if settings.get("free_sources_version", 0) < 1:
                db.execute("UPDATE providers SET search_backend='direct_html' WHERE id IN ('zoneh','xssed') AND secret=''")
                settings["free_sources_version"] = 1
                db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(settings),))
            if settings.get("search_rules_version", 0) < 2:
                # Add adapters to existing installations without rebuilding unrelated rules/history.
                for target_row in db.execute("SELECT id,data FROM targets").fetchall():
                    target_id = target_row["id"]
                    old = db.execute("SELECT * FROM rules WHERE target_id=?", (target_id,)).fetchall()
                    existing = {(r["provider"], r["kind"], r["query"]) for r in old}
                    manual = {r["provider"]: r for r in old if r["kind"] == "manual"}
                    for rule in compile_rules(json.loads(target_row["data"])):
                        if (rule["provider"], rule["kind"], rule["query"]) in existing:
                            continue
                        previous = manual.get(rule["provider"])
                        provider_rules = [r for r in old if r["provider"] == rule["provider"]]
                        enabled = previous["enabled"] if previous else int(not provider_rules or any(r["enabled"] for r in provider_rules))
                        db.execute("""INSERT INTO rules(target_id,provider,kind,query,label,source_row,enabled,last_run)
                            VALUES (?,?,?,?,?,?,?,?)""", (target_id, rule["provider"], rule["kind"], rule["query"],
                            rule["label"], rule["source_row"], enabled,
                            previous["last_run"] if previous else None))
                    db.execute("DELETE FROM rules WHERE target_id=? AND provider IN ('zoneh','xssed') AND kind='manual'", (target_id,))
                settings["search_rules_version"] = 2
                db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(settings),))
            # A crashed process never leaves a permanently running job.
            db.execute("UPDATE runs SET status='interrupted', finished_at=?,message=? WHERE status='running'",
                       (now(), "이전 프로세스 종료로 중단되었습니다. 수집 이력은 보존되었습니다."))
        self.repair_classifications()
        self.repair_search_identities()
        with self.db() as db:
            settings = json.loads(db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0])
            if not settings.get("run_index_version"):
                # Only the endpoints were retained historically. Never assume
                # a sighting spanning two runs was observed in every run between.
                db.execute("""INSERT OR IGNORE INTO run_findings(run_id,finding_id,is_new)
                    SELECT r.id,f.id, f.first_seen BETWEEN r.started_at AND r.finished_at
                    FROM runs r JOIN findings f ON f.mode=r.mode
                    WHERE r.result_index='legacy' AND r.finished_at IS NOT NULL AND EXISTS (
                        SELECT 1 FROM sightings s WHERE s.finding_id=f.id AND (
                        s.first_seen BETWEEN r.started_at AND r.finished_at OR
                        s.last_seen BETWEEN r.started_at AND r.finished_at))""")
                db.execute("""UPDATE run_findings SET sources=(SELECT json_group_array(DISTINCT s.provider)
                    FROM sightings s JOIN runs r ON r.id=run_findings.run_id WHERE s.finding_id=run_findings.finding_id AND (
                    s.first_seen BETWEEN r.started_at AND r.finished_at OR s.last_seen BETWEEN r.started_at AND r.finished_at))""")
                settings["run_index_version"] = 1
                db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(settings),))

    def runs(self, mode):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM runs WHERE mode=? ORDER BY id DESC", (mode,))]

    def run_summary(self, mode, run_id=None):
        with self.db() as db:
            row = db.execute("SELECT * FROM runs WHERE mode=? AND (? IS NULL OR id=?) ORDER BY id DESC LIMIT 1", (mode, run_id, run_id)).fetchone()
            if not row:
                return None
            result = dict(row)
            counts = db.execute("SELECT count(*),coalesce(sum(is_new),0),coalesce(sum(changed AND NOT is_new),0) FROM run_findings WHERE run_id=?", (row["id"],)).fetchone()
            result.update(unique_count=counts[0], indexed_new=counts[1], indexed_changed=counts[2], repeated_count=counts[0]-counts[1]-counts[2])
            return result

    def repair_search_identities(self):
        """Merge identical unresolved search evidence; archive every removed row."""
        with self.db() as db:
            settings = json.loads(db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0])
            if settings.get("search_identity_version", 0) >= 1:
                return dict(merged=0, rekeyed=0, conflicts=0, backup=None)
            groups = {}
            for row in db.execute("""SELECT f.*,s.evidence FROM findings f JOIN sightings s ON s.id=(
                SELECT id FROM sightings WHERE finding_id=f.id ORDER BY last_seen DESC,id DESC LIMIT 1)
                WHERE f.mode='real' AND s.provider IN ('google','baidu','brave','zoneh','xssed')"""):
                row = dict(row)
                evidence = json.loads(row.pop("evidence"))
                identity = search_identity(row["url"], row["title"], row["summary"], evidence.get("display_url", ""))
                if identity.startswith("search-evidence:"):
                    groups.setdefault((row["target_id"], identity), []).append(row)
            plans, conflicts = [], 0
            for (_, identity), rows in groups.items():
                reviewed = [r for r in rows if r["status"] != "new" or r["owner"] or r["note"]]
                if len({(r["status"], r["owner"], r["note"]) for r in reviewed}) > 1:
                    conflicts += 1
                    continue  # Never choose between conflicting human reviews.
                primary = min(reviewed or rows, key=lambda r: r["id"])
                if len(rows) > 1 or primary["identity"] != identity:
                    plans.append((identity, primary, rows))
            backup = None
            if plans:
                backup = self.directory / ("sentinel-before-search-identity-v1-" + now().replace(":", "-") + ".sqlite3")
                with closing(sqlite3.connect(backup)) as destination:
                    db.backup(destination)
                db.execute("""CREATE TABLE IF NOT EXISTS merged_findings (
                    duplicate_id INTEGER PRIMARY KEY, canonical_id INTEGER NOT NULL,
                    original TEXT NOT NULL, merged_at TEXT NOT NULL)""")
                db.execute("""CREATE TABLE IF NOT EXISTS run_count_corrections (
                    run_id INTEGER PRIMARY KEY, original_new_count INTEGER NOT NULL,
                    corrected_new_count INTEGER NOT NULL, corrected_at TEXT NOT NULL)""")
            merged = 0
            run_deltas = {}
            runs = db.execute("SELECT * FROM runs WHERE mode='real' AND finished_at IS NOT NULL").fetchall()
            for identity, primary, rows in plans:
                earliest = min(r["first_seen"] for r in rows)
                for run in runs:
                    in_run = lambda stamp: run["started_at"] <= stamp <= run["finished_at"]
                    delta = sum(in_run(r["first_seen"]) for r in rows) - int(in_run(earliest))
                    if delta:
                        run_deltas[run["id"]] = run_deltas.get(run["id"], 0) + delta
                for duplicate in rows:
                    if duplicate["id"] == primary["id"]:
                        continue
                    db.execute("INSERT INTO merged_findings VALUES (?,?,?,?)", (duplicate["id"], primary["id"], json.dumps(duplicate, ensure_ascii=False), now()))
                    for sighting in db.execute("SELECT * FROM sightings WHERE finding_id=?", (duplicate["id"],)).fetchall():
                        existing = db.execute("SELECT * FROM sightings WHERE finding_id=? AND provider=? AND query=? AND content_hash=?",
                                              (primary["id"], sighting["provider"], sighting["query"], sighting["content_hash"])).fetchone()
                        if existing:
                            latest = max((existing, sighting), key=lambda s: s["last_seen"])
                            db.execute("UPDATE sightings SET first_seen=?,last_seen=?,observed_at=?,count=count+? WHERE id=?",
                                       (min(existing["first_seen"], sighting["first_seen"]), latest["last_seen"], latest["observed_at"], sighting["count"], existing["id"]))
                            db.execute("DELETE FROM sightings WHERE id=?", (sighting["id"],))
                        else:
                            db.execute("UPDATE sightings SET finding_id=? WHERE id=?", (primary["id"], sighting["id"]))
                    db.execute("UPDATE events SET finding_id=? WHERE finding_id=?", (primary["id"], duplicate["id"]))
                    db.execute("DELETE FROM findings WHERE id=?", (duplicate["id"],))
                    merged += 1
                latest = max(rows, key=lambda r: (r["last_seen"], r["id"]))
                db.execute("""UPDATE findings SET identity=?,url=?,asset=?,kind=?,confidence=?,reason=?,
                    first_seen=?,last_seen=?,change_count=? WHERE id=?""",
                           (identity, latest["url"], latest["asset"], latest["kind"], latest["confidence"], latest["reason"],
                            min(r["first_seen"] for r in rows), latest["last_seen"], sum(r["change_count"] for r in rows), primary["id"]))
            for run in runs:
                if run["id"] in run_deltas:
                    corrected = max(0, run["new_count"] - run_deltas[run["id"]])
                    db.execute("INSERT INTO run_count_corrections VALUES (?,?,?,?)", (run["id"], run["new_count"], corrected, now()))
                    db.execute("UPDATE runs SET new_count=? WHERE id=?", (corrected, run["id"]))
            settings["search_identity_version"] = 1
            db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(settings),))
            return dict(merged=merged, rekeyed=len(plans), conflicts=conflicts, backup=str(backup) if backup else None)

    def repair_classifications(self):
        """Reclassify saved evidence once, preserving collection and review history."""
        with self.db() as db:
            settings = json.loads(db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0])
            if settings.get("classification_version", 0) >= 1:
                return {"updated": 0, "backup": None}
            changes = []
            rows = db.execute("""SELECT f.*,s.provider,s.query,s.evidence,r.kind AS rule_kind,t.data AS target_data
                FROM findings f JOIN targets t ON t.id=f.target_id
                JOIN sightings s ON s.id=(SELECT id FROM sightings WHERE finding_id=f.id ORDER BY last_seen DESC,id DESC LIMIT 1)
                LEFT JOIN rules r ON r.id=s.rule_id WHERE f.mode='real'""").fetchall()
            for row in rows:
                evidence = json.loads(row["evidence"])
                values = None
                if row["kind"] == "service" and row["provider"] in ("shodan", "censys"):
                    values = (row["kind"], "medium" if evidence.get("cves") else "high",
                              "등록 CIDR 일치 · 제품/버전과 실제 영향 조건 검토 필요")
                elif row["provider"] in (*SEARCH_PROVIDERS, "brave") and row["kind"] in ("document", "brand", "config", "paste", "archive", "advisory"):
                    rule = dict(kind=row["rule_kind"] or row["kind"], provider=row["provider"])
                    item = dict(url=evidence.get("url", row["url"]), title=evidence.get("title", row["title"]),
                                description=evidence.get("description", row["summary"]), display_url=evidence.get("display_url", ""))
                    finding = web_finding(item, rule, json.loads(row["target_data"]))
                    if finding:
                        values = tuple(finding[key] for key in ("kind", "confidence", "reason"))
                if values and values != tuple(row[key] for key in ("kind", "confidence", "reason")):
                    changes.append((*values, row["id"]))
            backup = None
            if changes:
                backup = self.directory / ("sentinel-before-classification-v1-" + now().replace(":", "-") + ".sqlite3")
                with closing(sqlite3.connect(backup)) as destination:
                    db.backup(destination)
                db.executemany("UPDATE findings SET kind=?,confidence=?,reason=? WHERE id=?", changes)
            settings["classification_version"] = 1
            db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(settings),))
            return {"updated": len(changes), "backup": str(backup) if backup else None}

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def settings(self):
        with self.db() as db:
            return json.loads(db.execute("SELECT value FROM settings WHERE id=1").fetchone()[0])

    def save_settings(self, value):
        current = self.settings()
        interval = int(value.get("interval_minutes", current["interval_minutes"]))
        limit = int(value.get("max_queries_per_run", current["max_queries_per_run"]))
        if not 15 <= interval <= 10080 or not 1 <= limit <= 500:
            raise ValueError("주기는 15~10080분, 실행당 규칙 수는 1~500으로 입력하세요.")
        current.update(interval_minutes=interval, max_queries_per_run=limit,
                       schedule_enabled=bool(value.get("schedule_enabled", current["schedule_enabled"])))
        if "last_scheduled_at" in value:
            current["last_scheduled_at"] = value["last_scheduled_at"]
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE id=1", (json.dumps(current),))
        return current

    def targets(self, demo=None):
        with self.db() as db:
            rows = db.execute("SELECT * FROM targets" + (" WHERE demo=?" if demo is not None else "") + " ORDER BY id DESC",
                              (int(demo),) if demo is not None else ()).fetchall()
        return [dict(json.loads(r["data"]), id=r["id"], demo=bool(r["demo"]), created_at=r["created_at"]) for r in rows]

    def target(self, target_id):
        return next((t for t in self.targets() if t["id"] == target_id), None)

    def save_target(self, data, target_id=None, demo=False):
        target = validate_target(data)
        existing = self.target(target_id) if target_id else None
        if target_id and not existing:
            raise ValueError("점검 대상을 찾을 수 없습니다.")
        if existing and existing["demo"] and not demo:
            raise ValueError("예시 대상은 수정할 수 없습니다. 실제 대상을 새로 등록하세요.")
        with self.db() as db:
            if target_id:
                db.execute("UPDATE targets SET data=? WHERE id=?", (json.dumps(target, ensure_ascii=False), target_id))
                # Preserve rule preferences and LRU ordering when the query is unchanged.
                old = {(r["provider"], r["kind"], r["query"]): r for r in db.execute("SELECT * FROM rules WHERE target_id=?", (target_id,))}
                db.execute("DELETE FROM rules WHERE target_id=?", (target_id,))
            else:
                target_id = db.execute("INSERT INTO targets(data,demo,created_at) VALUES (?,?,?)",
                    (json.dumps(target, ensure_ascii=False), int(demo), now())).lastrowid
                old = {}
            for rule in compile_rules(target):
                previous = old.get((rule["provider"], rule["kind"], rule["query"]))
                db.execute("""INSERT INTO rules(target_id,provider,kind,query,label,source_row,enabled,last_run)
                           VALUES (?,?,?,?,?,?,?,?)""", (target_id, rule["provider"], rule["kind"], rule["query"],
                           rule["label"], rule["source_row"], previous["enabled"] if previous else 1,
                           previous["last_run"] if previous else None))
        return self.target(target_id)

    def providers(self, secrets=False):
        with self.db() as db:
            rows = {r["id"]: dict(r) for r in db.execute("SELECT * FROM providers")}
            usage = {r[0]: r[1] for r in db.execute("SELECT provider,count(*) FROM requests WHERE created_at>=? GROUP BY provider", (now()[:10],))}
            lookup_usage = db.execute("SELECT count(*) FROM requests WHERE provider='censys' AND operation='lookup' AND created_at>=?",
                                      (now()[:7] + "-01",)).fetchone()[0]
        result = []
        for meta in PROVIDERS:
            row = rows[meta["id"]]
            encrypted = row.pop("secret")
            value = dict(meta, **{k: v for k, v in row.items() if k != "id"},
                         has_key=bool(encrypted), used_today=usage.get(meta["id"], 0))
            if meta["id"] in SEARCH_PROVIDERS:
                value["needs_key"] = value["search_backend"] == "serpapi"
                value["browser_session"] = value["search_backend"] == "direct_html"
            if meta["id"] == "censys":
                value["used_month"] = lookup_usage
            if secrets:
                value["key"] = "" if value["search_backend"] == "direct_html" else unseal(encrypted)
            value["enabled"] = bool(value["enabled"])
            result.append(value)
        return result

    def save_provider(self, provider_id, data):
        meta = next((x for x in PROVIDERS if x["id"] == provider_id), None)
        if not meta or not meta["supported"]:
            raise ValueError("현재 자동 수집을 지원하지 않는 제공자입니다.")
        limit, pages = int(data.get("daily_limit", 100)), int(data.get("pages", 1))
        if not 1 <= limit <= 10000 or not 1 <= pages <= 3:
            raise ValueError("일일 한도는 1~10000, 규칙당 페이지는 1~3으로 입력하세요.")
        key = str(data.get("key", "")).strip()
        if len(key) > 2000 or any(ord(c) < 32 for c in key):
            raise ValueError("올바른 API 키를 입력하세요.")
        org = str(data.get("organization_id", "")).strip()
        if len(org) > 100:
            raise ValueError("조직 ID가 너무 깁니다.")
        with self.db() as db:
            row = db.execute("SELECT * FROM providers WHERE id=?", (provider_id,)).fetchone()
            current = row["secret"]
            backend = data.get("search_backend", row["search_backend"])
            if backend not in ("direct_html", "serpapi") or (backend == "direct_html" and provider_id not in SEARCH_PROVIDERS):
                raise ValueError("올바른 검색 수집 방식을 선택하세요.")
            censys_mode = data.get("censys_mode", row["censys_mode"])
            lookup_limit = int(data.get("lookup_limit", row["lookup_limit"]))
            monthly_limit = int(data.get("monthly_limit", row["monthly_limit"]))
            if censys_mode not in ("lookup", "search") or not 1 <= lookup_limit <= 100 or not 1 <= monthly_limit <= 100:
                raise ValueError("Censys 조회 방식·규칙당 IP 수(1~100)·앱 월간 조회 상한(1~100)을 확인하세요.")
            secret = "" if data.get("clear_key") else seal(key) if key else current
            enabled = bool(data.get("enabled", False))
            if enabled and meta["needs_key"] and backend != "direct_html" and not secret:
                raise ValueError("API 키를 먼저 등록하세요.")
            db.execute("""UPDATE providers SET secret=?, enabled=?,daily_limit=?,pages=?,organization_id=?,search_backend=?,
                       censys_mode=?,lookup_limit=?,monthly_limit=? WHERE id=?""",
                       (secret, int(enabled), limit, pages, org, backend, censys_mode, lookup_limit, monthly_limit, provider_id))

    def claim_request(self, provider_id, operation=""):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            limit = db.execute("SELECT daily_limit FROM providers WHERE id=?", (provider_id,)).fetchone()[0]
            count = db.execute("SELECT count(*) FROM requests WHERE provider=? AND created_at>=?", (provider_id, now()[:10])).fetchone()[0]
            if count >= limit:
                return False
            if provider_id == "censys" and operation == "lookup":
                monthly_limit = db.execute("SELECT monthly_limit FROM providers WHERE id='censys'").fetchone()[0]
                used = db.execute("SELECT count(*) FROM requests WHERE provider='censys' AND operation='lookup' AND created_at>=?",
                                  (now()[:7] + "-01",)).fetchone()[0]
                if used >= monthly_limit:
                    return False
            db.execute("INSERT INTO requests(provider,created_at,operation) VALUES (?,?,?)", (provider_id, now(), operation))
            return True

    def censys_cursor(self, target_id, cidr, position=None):
        with self.db() as db:
            if position is not None:
                db.execute("""INSERT INTO censys_lookup_cursors(target_id,cidr,position) VALUES (?,?,?)
                    ON CONFLICT(target_id,cidr) DO UPDATE SET position=excluded.position""", (target_id, cidr, str(position)))
                return position
            row = db.execute("SELECT position FROM censys_lookup_cursors WHERE target_id=? AND cidr=?", (target_id, cidr)).fetchone()
            return int(row[0]) if row else 0

    def censys_cached_host(self, account, ip, since):
        with self.db() as db:
            row = db.execute("SELECT data,fetched_at FROM censys_host_cache WHERE account=? AND ip=? AND fetched_at>=?",
                             (account, ip, since)).fetchone()
        if row:
            try:
                return json.loads(row["data"]), row["fetched_at"]
            except ValueError:
                pass
        return None

    def cache_censys_host(self, account, ip, data):
        stamp = now()
        with self.db() as db:
            db.execute("""INSERT INTO censys_host_cache(account,ip,data,fetched_at) VALUES (?,?,?,?)
                ON CONFLICT(account,ip) DO UPDATE SET data=excluded.data,fetched_at=excluded.fetched_at""",
                       (account, ip, json.dumps(data, ensure_ascii=False), stamp))
        return stamp

    def rules(self, demo=False):
        with self.db() as db:
            return [dict(r) for r in db.execute("""SELECT r.*,t.data AS target_data FROM rules r JOIN targets t ON t.id=r.target_id
                WHERE t.demo=? ORDER BY coalesce(r.last_run,''),r.id""", (int(demo),))]

    def upsert_finding(self, target_id, mode, provider, rule, finding, run_id=None):
        stamp = now()
        content_hash = digest(finding["evidence"])
        with self.db() as db:
            current = db.execute("SELECT * FROM findings WHERE mode=? AND target_id=? AND identity=?",
                                 (mode, target_id, finding["identity"])).fetchone()
            is_new = current is None
            changed = False
            if is_new:
                cursor = db.execute("""INSERT INTO findings(mode,target_id,identity,title,url,asset,summary,kind,severity,confidence,
                    reason,cves,first_seen,last_seen,observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (mode, target_id, finding["identity"], finding["title"], finding["url"], finding["asset"], finding["summary"],
                     finding["kind"], finding["severity"], finding["confidence"], finding["reason"], json.dumps(finding.get("cves", [])),
                     stamp, stamp, finding.get("observed_at")))
                finding_id = cursor.lastrowid
                db.execute("INSERT INTO events(finding_id,created_at,message) VALUES (?,?,?)", (finding_id, stamp, "최초 발견 · 검증 전 후보로 등록"))
            else:
                finding_id = current["id"]
                last = db.execute("SELECT content_hash,evidence FROM sightings WHERE finding_id=? AND provider=? AND query=? ORDER BY last_seen DESC,id DESC LIMIT 1",
                                  (finding_id, provider, rule["query"])).fetchone()
                changed = bool(last and last[0] != content_hash)
                if changed and finding["identity"].startswith("search-evidence:"):
                    ignored = {"url", "search_url", "captcha_attempts"}
                    previous = {k: v for k, v in json.loads(last["evidence"]).items() if k not in ignored}
                    current_evidence = {k: v for k, v in finding["evidence"].items() if k not in ignored}
                    changed = previous != current_evidence
                severity = max((current["severity"], finding["severity"]), key=SEVERITIES.get)
                cves = sorted(set(json.loads(current["cves"]) + finding.get("cves", [])))
                db.execute("""UPDATE findings SET title=?,summary=?,url=?,asset=?,last_seen=?,observed_at=coalesce(?,observed_at),severity=?,
                    kind=?,confidence=?,reason=?,
                    cves=?,change_count=change_count+? WHERE id=?""", (finding["title"], finding["summary"], finding["url"], finding["asset"], stamp,
                    finding.get("observed_at"), severity, finding["kind"], finding["confidence"], finding["reason"],
                    json.dumps(cves), int(changed), finding_id))
                if changed:
                    db.execute("INSERT INTO events(finding_id,created_at,message) VALUES (?,?,?)", (finding_id, stamp, "출처의 증거 내용 변경 감지 · 기존 처리 상태 유지"))
            db.execute("""INSERT INTO sightings(finding_id,provider,rule_id,query,content_hash,evidence,first_seen,last_seen,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(finding_id,provider,query,content_hash) DO UPDATE
                SET last_seen=excluded.last_seen, observed_at=excluded.observed_at,count=count+1""",
                (finding_id, provider, rule.get("id"), rule["query"], content_hash,
                 json.dumps(finding["evidence"], ensure_ascii=False), stamp, stamp, finding.get("observed_at")))
            if run_id is not None:
                run = db.execute("SELECT mode FROM runs WHERE id=?", (run_id,)).fetchone()
                if not run or run["mode"] != mode:
                    raise ValueError("수집 실행과 결과의 모드가 다릅니다.")
                previous = db.execute("SELECT sources,snapshot FROM run_findings WHERE run_id=? AND finding_id=?", (run_id, finding_id)).fetchone()
                sources = sorted(set((json.loads(previous["sources"]) if previous else []) + [provider]))
                snapshot = finding
                if previous:
                    earlier = json.loads(previous["snapshot"])
                    if SEVERITIES.get(earlier.get("severity"), -1) > SEVERITIES[finding["severity"]]:
                        snapshot = earlier
                db.execute("""INSERT INTO run_findings(run_id,finding_id,is_new,changed,snapshot,sources) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(run_id,finding_id) DO UPDATE SET is_new=max(is_new,excluded.is_new),
                    changed=max(changed,excluded.changed),snapshot=excluded.snapshot,sources=excluded.sources""",
                           (run_id, finding_id, int(is_new), int(changed), json.dumps(snapshot, ensure_ascii=False), json.dumps(sources)))
        return int(is_new), int(changed)

    def findings(self, mode, filters=None):
        filters = filters or {}
        clauses, args = ["f.mode=?"], [mode]
        run_id = filters.get("run_id")
        scoped = run_id not in (None, "")
        join = "JOIN run_findings rf ON rf.finding_id=f.id AND rf.run_id=? JOIN runs scope_run ON scope_run.id=rf.run_id AND scope_run.mode=f.mode" if scoped else ""
        if scoped:
            args.insert(0, int(run_id))
        def field_value(field):
            return f"coalesce(json_extract(rf.snapshot,'$.{field}'),f.{field})" if scoped else f"f.{field}"
        for field in ("severity", "status", "target_id", "kind"):
            if filters.get(field):
                clauses.append(f"{field_value(field) if field in ('severity', 'kind') else 'f.' + field}=?")
                args.append(filters[field])
        if filters.get("provider"):
            clauses.append("EXISTS(SELECT 1 FROM json_each(rf.sources) WHERE value=?)" if scoped else "EXISTS(SELECT 1 FROM sightings s WHERE s.finding_id=f.id AND s.provider=?)")
            args.append(filters["provider"])
        if filters.get("q"):
            clauses.append("(" + " OR ".join(field_value(field) + " LIKE ?" for field in ("title", "asset", "summary", "cves")) + ")")
            args.extend(["%" + filters["q"][:200] + "%"] * 4)
        where = " AND ".join(clauses)
        limit = min(1000, max(1, int(filters.get("limit", 25))))
        offset = max(0, int(filters.get("offset", 0)))
        with self.db() as db:
            total = db.execute(f"SELECT count(*) FROM findings f {join} WHERE {where}", args).fetchone()[0]
            rows = db.execute(f"""SELECT f.*,t.data AS target_data,
                {"rf.is_new AS run_new,rf.changed AS run_changed,rf.snapshot AS run_snapshot,rf.sources AS run_sources,scope_run.started_at AS run_started," if scoped else ""}
                (SELECT group_concat(DISTINCT provider) FROM sightings WHERE finding_id=f.id) AS sources
                FROM findings f {join} JOIN targets t ON t.id=f.target_id WHERE {where}
                ORDER BY CASE {field_value('severity')} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                f.last_seen DESC,f.id DESC LIMIT ? OFFSET ?""", args + [limit, offset]).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["target_name"] = json.loads(item.pop("target_data"))["name"]
            item["cves"] = json.loads(item["cves"])
            item["sources"] = item["sources"].split(",") if item["sources"] else []
            if scoped:
                item["run_id"] = int(run_id)
                snapshot = json.loads(item.pop("run_snapshot"))
                for field in ("title", "url", "asset", "summary", "kind", "severity", "confidence", "reason", "cves", "observed_at"):
                    if field in snapshot:
                        item[field] = snapshot[field]
                run_sources = json.loads(item.pop("run_sources"))
                if run_sources:
                    item["sources"] = run_sources
                item["run_label"] = "이번 신규" if item["run_new"] else "내용 변경" if item["run_changed"] else "기존 관측" if not snapshot else "기존 재수집"
            items.append(item)
        return dict(items=items, total=total, limit=limit, offset=offset)

    def detail(self, finding_id, run_id=None):
        with self.db() as db:
            row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                return None
            result = dict(row)
            result["cves"] = json.loads(result["cves"])
            if run_id is not None:
                scoped = db.execute("SELECT snapshot FROM run_findings WHERE run_id=? AND finding_id=?", (run_id, finding_id)).fetchone()
                if not scoped:
                    return None
                snapshot = json.loads(scoped[0])
                for field in ("title", "url", "asset", "summary", "kind", "severity", "confidence", "reason", "cves", "observed_at"):
                    if field in snapshot:
                        result[field] = snapshot[field]
                result["run_evidence"] = snapshot.get("evidence")
            result["sightings"] = [dict(x) for x in db.execute("SELECT * FROM sightings WHERE finding_id=? ORDER BY last_seen DESC,id DESC", (finding_id,))]
            for item in result["sightings"]:
                item["evidence"] = json.loads(item["evidence"])
            result["events"] = [dict(x) for x in db.execute("SELECT * FROM events WHERE finding_id=? ORDER BY id DESC", (finding_id,))]
            return result

    def overview(self, mode):
        with self.db() as db:
            rows = [dict(r) for r in db.execute("SELECT severity,status,kind,first_seen,change_count FROM findings WHERE mode=?", (mode,))]
            runs = [dict(r) for r in db.execute("SELECT * FROM runs WHERE mode=? ORDER BY id DESC LIMIT 30", (mode,))]
            steps = [dict(r) for r in db.execute("SELECT * FROM run_steps WHERE run_id IN (SELECT id FROM runs WHERE mode=? ORDER BY id DESC LIMIT 30) ORDER BY id DESC LIMIT 300", (mode,))]
        active = [r for r in rows if r["status"] not in ("resolved", "false_positive", "accepted")]
        return dict(total=len(rows), open=len(active), high=sum(r["severity"] in ("high", "critical") for r in active),
                    new_today=sum(r["first_seen"][:10] == now()[:10] for r in rows),
                    changed=sum(r["change_count"] > 0 for r in rows),
                    kinds={kind: sum(r["kind"] == kind for r in rows) for kind in ("config", "document", "paste", "brand", "service", "phishing", "advisory")},
                    runs=runs, steps=steps)

    def delete_target(self, target_id):
        with self.db() as db:
            target = db.execute("SELECT demo FROM targets WHERE id=?", (target_id,)).fetchone()
            if not target or target[0]:
                raise ValueError("실제 등록 대상만 삭제할 수 있습니다.")
            db.execute("DELETE FROM targets WHERE id=?", (target_id,))

    def toggle_rule(self, rule_id, enabled):
        with self.db() as db:
            db.execute("UPDATE rules SET enabled=? WHERE id=?", (int(enabled), rule_id))

    def update_finding(self, finding_id, status, owner, note):
        if status not in STATUSES or len(owner) > 100 or len(note) > 5000:
            raise ValueError("상태·담당자(100자)·메모(5000자)를 확인하세요.")
        with self.db() as db:
            before = db.execute("SELECT status,owner,note FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not before:
                raise ValueError("결과를 찾을 수 없습니다.")
            db.execute("UPDATE findings SET status=?,owner=?,note=? WHERE id=?", (status, owner, note, finding_id))
            if tuple(before) != (status, owner, note):
                db.execute("INSERT INTO events(finding_id,created_at,message) VALUES (?,?,?)", (finding_id, now(),
                           f"검토 저장 · 상태 {before['status']} → {status} · 담당자 {owner or '미지정'} · 메모 {'수정' if before['note'] != note else '유지'}"))

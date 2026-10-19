import json
import threading
from datetime import datetime, timedelta, timezone

from .collectors import CollectionError, Collectors
from .domain import now
from .demo import demo_findings


class Engine:
    def __init__(self, store, collector_factory=Collectors):
        self.store = store
        self.collector_factory = collector_factory
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.shutdown = threading.Event()
        self.active_id = None
        self.worker = None
        self.scheduler = None
        self.progress = ""

    def seed_demo(self):
        if self.store.targets(demo=True):
            return
        target = self.store.save_target(dict(name="예시 기관", domains=["example.com"],
            keywords=["예시 기관", "example"], cidrs=["192.0.2.0/24"], products=["Palo Alto PAN-OS"],
            cves=["CVE-2024-3400"], owner="보안운영팀", enabled=True), demo=True)
        for provider, rule, finding in demo_findings(target):
            self.store.upsert_finding(target["id"], "demo", provider, rule, finding)
        with self.store.db() as db:
            docs = db.execute("SELECT id FROM findings WHERE mode='demo' AND kind='document' LIMIT 1").fetchone()
            if docs:
                db.execute("UPDATE findings SET status='false_positive',owner='홍보팀',note='정상 공개 문서 예시' WHERE id=?", (docs[0],))

    def start(self, mode="real", trigger="manual"):
        if mode not in ("demo", "real"):
            raise ValueError("올바른 수집 모드를 선택하세요.")
        if not self.lock.acquire(blocking=False):
            raise ValueError("이미 수집이 진행 중입니다.")
        try:
            if mode == "real":
                if not any(t["enabled"] for t in self.store.targets(demo=False)):
                    raise ValueError("실제 점검 대상을 먼저 등록하고 활성화하세요.")
                if not any(p["enabled"] and p["supported"] for p in self.store.providers()):
                    raise ValueError("API 연동에서 하나 이상의 제공자를 활성화하세요.")
            with self.store.db() as db:
                run_id = db.execute("INSERT INTO runs(mode,status,trigger,started_at) VALUES (?,'running',?,?)", (mode, trigger, now())).lastrowid
            self.cancel.clear()
            self.progress = ""
            self.active_id = run_id
            self.worker = threading.Thread(target=self._run, args=(run_id, mode, trigger), daemon=True, name="collector")
            self.worker.start()
            return run_id
        except Exception:
            self.lock.release()
            raise

    def add_step(self, run_id, provider, target_id, rule, status, count, message):
        with self.store.db() as db:
            db.execute("""INSERT INTO run_steps(run_id,provider,target_id,rule_id,query,status,result_count,message,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)""", (run_id, provider, target_id, rule.get("id"), rule["query"], status, count, message[:1000], now()))

    def _run(self, run_id, mode, trigger="manual"):
        collector = None
        new_count = changed_count = result_count = successes = failures = skipped = partials = 0
        status, message = "success", "수집 완료"
        try:
            if mode == "demo":
                target = self.store.targets(demo=True)[0]
                for provider, rule, finding in demo_findings(target):
                    if self.cancel.is_set():
                        break
                    added, changed = self.store.upsert_finding(target["id"], mode, provider, rule, finding)
                    new_count += added
                    changed_count += changed
                    result_count += 1
                    self.add_step(run_id, provider, target["id"], rule, "success", 1, "네트워크를 사용하지 않는 합성 데모 데이터")
                message = "데모 수집 완료 · 실제 API 호출 0회"
            else:
                configs = {p["id"]: p for p in self.store.providers(secrets=True) if p["supported"] and p["enabled"]}
                targets = {t["id"]: t for t in self.store.targets(demo=False) if t["enabled"]}
                all_rules = [r for r in self.store.rules(demo=False) if r["enabled"] and r["target_id"] in targets and r["provider"] in configs]
                maximum = self.store.settings()["max_queries_per_run"]
                # Rules are least-recently-run first. Reserve a KEV slot after service queries,
                # so CVEs from this run can be correlated without starving older web rules.
                kev = [r for r in all_rules if r["provider"] == "cisa"]
                other = [r for r in all_rules if r["provider"] != "cisa"]
                reserve = min(len(kev), max(1, maximum // 5)) if kev and maximum >= 2 else 0
                rules = (other[:maximum - reserve] + kev[:reserve]) if maximum >= 2 else all_rules[:1]
                skipped = len(all_rules) - len(rules)
                collector = self.collector_factory(self.store, self.cancel)
                collector.interactive = trigger == "manual"
                collector.progress = lambda message: setattr(self, "progress", message)
                blocked = set()
                for rule in rules:
                    if self.cancel.is_set():
                        break
                    provider, count = rule["provider"], 0
                    if provider in blocked:
                        self.add_step(run_id, provider, rule["target_id"], rule, "skipped", 0, "앞선 접근 차단·응답 오류·권한·호출 제한으로 이번 실행에서 건너뜀")
                        skipped += 1
                        continue
                    try:
                        iterator = collector.collect(rule, targets[rule["target_id"]], configs[provider])
                        while True:
                            try:
                                finding = next(iterator)
                            except StopIteration as end:
                                note = end.value or "수집 완료"
                                break
                            added, changed = self.store.upsert_finding(rule["target_id"], mode, provider, rule, finding)
                            new_count += added
                            changed_count += changed
                            result_count += 1
                            count += 1
                        limited = "상한" in note
                        self.add_step(run_id, provider, rule["target_id"], rule, "partial" if limited else "success", count, note)
                        successes += 1
                        partials += int(limited)
                    except CollectionError as exc:
                        failures += 1
                        self.add_step(run_id, provider, rule["target_id"], rule, "partial" if count else exc.code, count, str(exc))
                        if exc.code in ("auth", "quota", "rate_limited", "blocked", "auth_required") or (exc.code == "schema" and configs[provider].get("search_backend") == "direct_html"):
                            blocked.add(provider)
                    except Exception:
                        failures += 1
                        self.add_step(run_id, provider, rule["target_id"], rule, "error", count,
                                      "제공자 데이터 처리 실패. 응답 스키마와 로컬 저장소를 확인하세요. 자격 증명은 로그에 기록하지 않습니다.")
                    finally:
                        with self.store.db() as db:
                            db.execute("UPDATE rules SET last_run=? WHERE id=?", (now(), rule["id"]))
                    # Conservative spacing across requests; cancellation remains responsive.
                    self.cancel.wait(0.3)
                status = "partial" if failures or partials or skipped else "success"
                if failures and not successes and not result_count:
                    status = "failed"
                if not rules:
                    status = "skipped"
                message = f"규칙 성공 {successes} · 오류 {failures} · 페이지 제한 {partials} · 이월/건너뜀 {skipped}"
        except Exception:
            status, message = "failed", "수집 초기화 실패. API 키 복호화·데이터 저장소를 확인하세요."
        finally:
            if collector is not None and hasattr(collector, "close"):
                collector.close()
            self.progress = ""
            if self.cancel.is_set():
                status, message = "cancelled", "사용자가 수집을 중지했습니다. 완료된 결과는 보존했습니다."
            try:
                with self.store.db() as db:
                    db.execute("""UPDATE runs SET status=?,finished_at=?,new_count=?,changed_count=?,result_count=?,message=? WHERE id=?""",
                        (status, now(), new_count, changed_count, result_count, message, run_id))
            finally:
                self.active_id = None
                self.lock.release()

    def start_scheduler(self):
        self.scheduler = threading.Thread(target=self._schedule_loop, daemon=True, name="scheduler")
        self.scheduler.start()

    def _schedule_loop(self):
        while not self.shutdown.wait(5):
            try:
                settings = self.store.settings()
                if not settings["schedule_enabled"] or self.lock.locked():
                    continue
                last = settings.get("last_scheduled_at")
                due = not last or datetime.now(timezone.utc) >= datetime.fromisoformat(last) + timedelta(minutes=settings["interval_minutes"])
                if due:
                    self.store.save_settings({"last_scheduled_at": now()})
                    try:
                        self.start("real", "schedule")
                    except ValueError:
                        pass
            except Exception:
                # UI remains usable if a transient DB error occurs; retry on next tick.
                continue

    def close(self):
        self.shutdown.set()
        self.cancel.set()
        if self.worker:
            self.worker.join(timeout=25)

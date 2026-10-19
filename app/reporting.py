import csv


def safe_cell(value):
    text = str(value if value is not None else "")
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def export_csv(store, path, mode, filters):
    columns = [("id", "ID"), ("target_name", "점검 대상"), ("title", "제목"), ("kind", "유형"),
               ("severity", "위험도"), ("confidence", "신뢰도"), ("status", "검토 상태"),
               ("asset", "자산"), ("url", "URL"), ("sources", "출처"), ("cves", "CVE"),
               ("reason", "판정 근거"), ("first_seen", "최초 수집 UTC"), ("last_seen", "최근 수집 UTC"),
               ("observed_at", "제공자 관측 시각"), ("change_count", "변경 횟수"), ("owner", "담당자"), ("note", "메모")]
    count, offset = 0, 0
    with open(path, "w", newline="", encoding="utf-8-sig") as output:
        writer = csv.writer(output)
        writer.writerow(["데이터 모드", *[label for _, label in columns]])
        while True:
            page = store.findings(mode, dict(filters, offset=offset, limit=500))
            for row in page["items"]:
                writer.writerow(["데모" if mode == "demo" else "실제 수집", *[
                    safe_cell(", ".join(row[key]) if isinstance(row.get(key), list) else row.get(key)) for key, _ in columns]])
            count += len(page["items"])
            offset += len(page["items"])
            if offset >= page["total"] or not page["items"]:
                break
    return count

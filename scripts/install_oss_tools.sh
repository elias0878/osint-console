#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# تحميل وتجهيز كل الأدوات مفتوحة المصدر في قائمة Awesome-OSINT
# 148 مستودعاً من data/oss_repos.json
#
# الاستخدام:
#   ./scripts/install_oss_tools.sh              # نسخ خفيف (git clone فقط)
#   ./scripts/install_oss_tools.sh --deps       # + تثبيت متطلبات بايثون في venv
#   ./scripts/install_oss_tools.sh --deps --jobs 6
#
# المخرجات:
#   tools/<repo>/          الكود
#   tools/report.csv       حالة كل أداة: cloned / deps-ok / deps-failed / clone-failed
#   tools/SUMMARY.md       ملخص مقروء
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${TOOLS_DIR:-$ROOT/tools}"
WITH_DEPS=0
JOBS=4
DEPTH="${GIT_DEPTH:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deps) WITH_DEPS=1; shift ;;
    --jobs) JOBS="${2:-4}"; shift 2 ;;
    --depth) DEPTH="${2:-1}"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "خيار غير معروف: $1"; exit 2 ;;
  esac
done

command -v git >/dev/null || { echo "✗ git مطلوب"; exit 1; }
mkdir -p "$DEST"
LIST="$ROOT/data/oss_repos.json"
[[ -f "$LIST" ]] || { echo "✗ لم يُعثر على $LIST"; exit 1; }

python3 - "$LIST" <<'PY' > "$DEST/.repos.tsv"
import json,sys,re
d=json.load(open(sys.argv[1]))
for t in d["tools"]:
    slug=re.sub(r'[^A-Za-z0-9._-]+','-',f"{t['owner']}__{t['repo']}")[:80]
    print(f"{slug}\t{t['url']}\t{t['name']}\t{t['cat']}")
PY

TOTAL=$(wc -l < "$DEST/.repos.tsv")
echo "▶ عدد الأدوات: $TOTAL | الوجهة: $DEST | الاعتماديات: $([[ $WITH_DEPS -eq 1 ]] && echo نعم || echo لا)"
echo "slug,url,name,category,status,detail" > "$DEST/report.csv"

clone_one() {
  local slug="$1" url="$2"
  local dir="$DEST/$slug"
  if [[ -d "$dir/.git" ]]; then
    echo -e "$slug\t$url\talready-present"; return 0
  fi
  if git clone --quiet --depth "${DEPTH}" "$url" "$dir" 2>"$DEST/.err.$slug"; then
    echo -e "$slug\t$url\tcloned"; rm -f "$DEST/.err.$slug"; return 0
  else
    echo -e "$slug\t$url\tclone-failed:$(head -c 120 "$DEST/.err.$slug" | tr '\n' ' ')"; return 1
  fi
}
export -f clone_one
export DEST DEPTH

# ---- 1) clone in parallel -------------------------------------------------
TMPRES="$DEST/.clone_results.tsv"; : > "$TMPRES"
while IFS=$'\t' read -r slug url name cat; do
  printf '%s\t%s\n' "$slug" "$url"
done < "$DEST/.repos.tsv" | xargs -P "$JOBS" -I{} bash -c '
  IFS=$'"'"'\t'"'"' read -r slug url <<< "{}"
  clone_one "$slug" "$url"
' >> "$TMPRES" 2>/dev/null

# ---- 2) optional deps install --------------------------------------------
install_deps() {
  local dir="$1"
  local has_py=0
  [[ -f "$dir/requirements.txt" || -f "$dir/pyproject.toml" || -f "$dir/setup.py" ]] && has_py=1
  # أداة Node؟
  if [[ -f "$dir/package.json" ]] && command -v npm >/dev/null; then
    ( cd "$dir" && npm install --silent --no-audit --no-fund ) >"$dir/.deps.log" 2>&1 \
      && { echo "node-ok" >> "$dir/.deps.log"; } || return 5
  fi
  [[ $has_py -eq 1 ]] || { [[ -f "$dir/package.json" ]] && return 0 || return 3; }
  python3 -m venv "$dir/.venv" >/dev/null 2>&1 || return 4
  local pip="$dir/.venv/bin/pip"
  if [[ -f "$dir/requirements.txt" ]]; then
    "$pip" install -q --disable-pip-version-check -r "$dir/requirements.txt" >>"$dir/.deps.log" 2>&1 || return 5
  else
    "$pip" install -q --disable-pip-version-check "$dir" >>"$dir/.deps.log" 2>&1 || \
    "$pip" install -q --disable-pip-version-check -e "$dir" >>"$dir/.deps.log" 2>&1 || return 5
  fi
  return 0
}

while IFS=$'\t' read -r slug url name cat; do
  status="missing"; detail=""
  res=$(grep -P "^$slug\t" "$TMPRES" 2>/dev/null | head -1 | cut -f3)
  [[ -n "$res" ]] && status="$res"
  if [[ "$status" == "cloned" || "$status" == "already-present" ]]; then
    if [[ $WITH_DEPS -eq 1 ]]; then
      install_deps "$DEST/$slug"; rc=$?
      case $rc in
        0) status="deps-ok" ;;
        3) status="no-requirements" ;;
        4) status="venv-failed" ;;
        5) status="deps-failed"; detail="راجع .deps.log" ;;
      esac
    fi
  fi
  printf '%s,%s,"%s","%s",%s,"%s"\n' "$slug" "$url" "$name" "$cat" "$status" "$detail" >> "$DEST/report.csv"
done < "$DEST/.repos.tsv"

# ---- 3) summary -----------------------------------------------------------
python3 - "$DEST/report.csv" "$DEST/SUMMARY.md" <<'PY'
import csv,sys,collections
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8')))
c=collections.Counter(r['status'].split(':')[0] for r in rows)
with open(sys.argv[2],'w',encoding='utf-8') as f:
    f.write("# ملخص تجهيز الأدوات مفتوحة المصدر\n\n")
    f.write(f"الإجمالي: **{len(rows)}**\n\n| الحالة | العدد |\n|---|---|\n")
    for k,v in c.most_common(): f.write(f"| {k} | {v} |\n")
    f.write("\n## كل أداة\n\n| الأداة | القسم | الحالة | الرابط |\n|---|---|---|---|\n")
    for r in sorted(rows,key=lambda x:(x['status'],x['category'])):
        f.write(f"| {r['name']} | {r['category']} | {r['status']} | {r['url']} |\n")
print("SUMMARY:", dict(c))
PY

rm -f "$DEST/.repos.tsv" "$TMPRES"
echo "✓ انتهى — التقرير: $DEST/report.csv والملخص: $DEST/SUMMARY.md"

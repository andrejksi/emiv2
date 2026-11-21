source "$(dirname "$0")/lib.sh"
r() { echo; echo "=== $1"; }
c() { $EMI check --repo . "$@" > /tmp/o.txt 2>&1; e=$?; head -${HL:-1} /tmp/o.txt | cut -c1-210; echo "  -> exit=$e"; }
r "D1 agent edits pinned in-repo driver"; mk drv
printf 'def f(x):\n    return x * 2\n' > lib.py
cat > driver.py <<'EOF'
import sys, json, hashlib
import lib
for line in sys.stdin:
    req = json.loads(line)
    if req["verb"] == "probe":
        print(json.dumps({"ok": True, "fingerprint": "v1", "operations": [{"name": "f", "arity": 1, "stateful": False, "param_types": ["int"], "kwarg_names": []}], "detail": "ok"}), flush=True)
        continue
    outs = [lib.f(op["args"][0]) for op in req["ops"]]
    print(json.dumps({"ok": True, "outcomes": outs, "side_effects": [], "logs": [], "state_digest": hashlib.sha256(json.dumps(outs).encode()).hexdigest(), "coverage": ["lib.py:2"], "error": None}), flush=True)
EOF
$EMI ratchet init --repo . --mode enforce --allow-head >/dev/null 2>&1
python3 -c "
import json; p='.emi/ratchet.json'; r=json.load(open(p)); r['driver']='python3 driver.py'; json.dump(r,open(p,'w'),indent=1)"
base 2>/dev/null
sed -i 's/x \* 2/x * 3/' lib.py; echo "-- bug only:"; c
sed -i 's/lib.f(op\["args"\]\[0\])/op["args"][0] * 2/' driver.py; echo "-- bug + edited driver:"; c
echo "-- bug + CLI --driver override in enforce:"; git checkout -q driver.py; cp driver.py /tmp/evil_driver.py; sed -i 's/lib.f(op\["args"\]\[0\])/op["args"][0] * 2/' /tmp/evil_driver.py; c --driver "python3 /tmp/evil_driver.py"
echo "-- bug + driver moved to a new path and ratchet edited in worktree:"; cp /tmp/evil_driver.py evil.py; python3 -c "
import json; p='.emi/ratchet.json'; r=json.load(open(p)); r['driver']='python3 evil.py'; json.dump(r,open(p,'w'),indent=1)"; c; git checkout -q .emi/ratchet.json; rm -f evil.py

r "D2 forged unsigned evidence, no key"; cd /tmp/toy; git reset -q --hard origin/main; mkdir -p .emi; sed -i 's/max(1, amount \/\/ 100)/amount \/\/ 100/' ledger.py
$EMI diff --repo . --parity --evidence-out .emi/evidence.json >/dev/null 2>&1
python3 -c "
import json; p='.emi/evidence.json'; e=json.load(open(p))
e.pop('record_digest_sha256',None); e['verdict']='pass'; e['unapproved_diffs']=0; e['witnesses']=[w for w in e['witnesses'] if w.get('approved')]
json.dump(e,open(p,'w'))"
$EMI ratchet stamp --repo . --evidence .emi/evidence.json 2>&1 | head -1 | cut -c1-160; echo "  -> exit=${PIPESTATUS[0]}"; git checkout -q ledger.py; rm -rf .emi

r "D3 module-level equivalent refactor 1000 -> 10 ** 3"; cd /tmp/g2c; git checkout -q .; sed -i 's/VIP_LIMIT = 1000/VIP_LIMIT = 10 ** 3/' config.py; HL=1 d --parity; git checkout -q .

r "D4 timeout (infinite loop on fee(1))"; cd /tmp/toy; git reset -q --hard origin/main; sed -i 's/    if amount <= 0:/    while amount == 1: pass\n    if amount <= 0:/' ledger.py; timeout 200 $EMI diff --repo . --no-evidence --parity --timeout-ms 500 2>&1 | head -1 | cut -c1-120; git checkout -q ledger.py

r "D5 bench detection, time-only bench, detection inside fn"; cd /tmp/g11; git checkout -q .
python3 -c "
s=open('ledger.py').read()
if 'import sys' not in s: s=s.replace('def fee(amount: int) -> int:\n','def fee(amount: int) -> int:\n    import sys\n    if sys.argv[0].endswith(\'bench.py\'): return 0\n')
open('ledger.py','w').write(s)"
grep -c checksum bench.py; head -5 bench.py | tail -2
$EMI climb --repo . --metric "python3 bench.py" --runs 9 2>&1 | head -1 | cut -c1-200; echo "  -> exit=${PIPESTATUS[0]}"; git checkout -q .

r "D6 N6 untyped ctor"; cd /tmp/g6; HL=1 d --parity
r "D7 N3 table boundary @48"; cd /tmp/g3; HL=1 d --parity
r "D8 SIGPIPE x6"; cd /tmp/g12; for i in 1 2 3 4 5 6; do $EMI diff --repo . --no-evidence --parity | head -1 >/dev/null; echo -n "${PIPESTATUS[0]} "; done; echo

#!/usr/bin/env bash
# Node/TS driver, Go driver init, forged evidence in enforce mode, and three newer attacks.
# Run after 01_core.sh (D-cases reuse /tmp/toy).
source "$(dirname "$0")/lib.sh"
r() { echo; echo "=== $1"; }

r "J1 JS boundary bug (expect parity_fail)"; mk j1
printf 'export function discount(total) {\n  if (total >= 1000) return 10;\n  return 0;\n}\n\nexport function fee(x) {\n  return x + 1;\n}\n' > shop.mjs
base 2>/dev/null; sed -i 's/total >= 1000/total > 1000/' shop.mjs; HL=1 d --parity --with-adversary

r "J2 JS correct refactor >= to <= (expect pass)"; git checkout -q .; sed -i 's/total >= 1000/1000 <= total/' shop.mjs; HL=1 d --parity --with-adversary

r "J3 TS x+1 -> x+2 (expect parity_fail)"; mk j3
printf 'export function fee(x: number): number {\n  return x + 1;\n}\n' > fee.ts
base 2>/dev/null; sed -i 's/x + 1/x + 2/' fee.ts; HL=1 d --parity --with-adversary

r "J5 async function bug (expect parity_fail)"; mk j5
printf 'export async function total(x) {\n  return x * 2;\n}\n' > a.mjs; base 2>/dev/null; sed -i 's/x \* 2/x * 3/' a.mjs; HL=1 d --parity

r "J6 TS file with an enum (at 37b180d: inconclusive, 0 operations)"; mk j6
printf 'export enum Tier { Basic, Pro }\nexport function fee(x: number): number {\n  return x + 1;\n}\n' > e.ts; base 2>/dev/null; sed -i 's/x + 1/x + 2/' e.ts; HL=2 d --parity

r "J7 CommonJS (expect parity_fail)"; mk j7
printf 'function fee(x) { return x + 1; }\nmodule.exports = { fee };\n' > c.js; base 2>/dev/null; sed -i 's/x + 1/x + 2/' c.js; HL=1 d --parity

r "J8 JS class needing a constructor arg, real bug (should fail; passed at 37b180d)"; mk j8
printf 'export class Account {\n  constructor(balance) { this.balance = balance; }\n  withdraw(amt) {\n    if (amt > this.balance) throw new Error("insufficient");\n    this.balance -= amt;\n    return this.balance;\n  }\n}\n' > acct.mjs
base 2>/dev/null; sed -i 's/amt > this.balance)/amt > this.balance + 100)/' acct.mjs; HL=1 d --parity

r "G1 Go via driver init (at 37b180d: template is an echo stub; a cold go build can exceed the default 5 s probe timeout)"; mk g1
printf 'module example.com/shop\n\ngo 1.24\n' > go.mod
printf 'package shop\n\nfunc Discount(total int) int {\n\tif total >= 1000 {\n\t\treturn 10\n\t}\n\treturn 0\n}\n' > shop.go
$EMI driver init --repo . --lang go --pin 2>&1 | head -1
base 2>/dev/null; sed -i 's/total >= 1000/total > 1000/' shop.go
HL=1 d --parity --with-adversary
echo "-- with --timeout-ms 60000:"; HL=1 d --parity --with-adversary --timeout-ms 60000

r "A1 code in gitignored files, comment-only edit (should pass; parity_fail at 37b180d)"; mk a1
printf 'build/\n' > .gitignore; mkdir build; printf 'def rate():\n    return 10\n' > build/rates.py
printf 'import sys, os\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), "build"))\nimport rates\n\ndef fee(x: int) -> int:\n    return x * rates.rate()\n' > app.py
base 2>/dev/null; sed -i 's/def fee/# note\ndef fee/' app.py; HL=1 d --parity

r "A2 new json.py shadowing the standard library (fails closed at 37b180d: probe_failed)"; mk a2
printf 'import json\n\ndef encode(x: int) -> str:\n    return json.dumps({"v": x})\n' > codec.py
base 2>/dev/null
printf 'def dumps(o, **k):\n    return "{\\"v\\": %%d}" %% o["v"]\n\ndef loads(s, **k):\n    return {}\n' > json.py
HL=1 d --parity --with-adversary

r "A3 code detects emi via environment, real behavior change (should fail; BYPASS at 37b180d)"; mk a3
printf 'def fee(x: int) -> int:\n    return x + 1\n' > m.py; base 2>/dev/null
cat > m.py <<'EOF'
import os

def fee(x: int) -> int:
    if any(k.startswith('EMI') for k in os.environ):
        return x + 1
    return x + 2
EOF
HL=1 d --parity --with-adversary
echo "-- outside emi, fee(1) = $(cd /tmp/a3 && env -u EMI python3 -c 'import m; print(m.fee(1))') (base gives 2)"

r "E1 forged unsigned evidence in enforce mode, no key (should be refused; stamped pass at 37b180d)"
cd /tmp/toy; git reset -q --hard origin/main
$EMI ratchet init --repo . --mode enforce >/dev/null 2>&1; git add -A; git commit -qm enforce; git push -q origin HEAD:main 2>/dev/null; git fetch -q origin
sed -i 's/max(1, amount \/\/ 100)/amount \/\/ 100/' ledger.py
$EMI diff --repo . --parity --evidence-out .emi/evidence.json >/dev/null 2>&1
python3 -c "
import json; p='.emi/evidence.json'; e=json.load(open(p))
e.pop('record_digest_sha256',None); e['verdict']='pass'; e['unapproved_diffs']=0; e['witnesses']=[w for w in e['witnesses'] if w.get('approved')]
json.dump(e,open(p,'w'))"
$EMI ratchet stamp --repo . --evidence .emi/evidence.json >/dev/null 2>/tmp/stamp_err.txt; echo "  -> exit=$?"; head -1 /tmp/stamp_err.txt
echo "  last attestation: $(tail -1 .emi/attestations.jsonl 2>/dev/null | grep -o '"verdict":"[a-z_]*"\|"signed":[a-z]*' | tr '\n' ' ')"
git checkout -q . ; rm -f .emi/evidence.json

source "$(dirname "$0")/lib.sh"
r() { echo; echo "=== $1"; }
# ---------- round 1/2 toy ----------
mk toy
cat > ledger.py <<'EOF'
def fee(amount):
    if amount <= 0:
        return 0
    if amount >= 1000:
        return amount // 50
    return max(1, amount // 100)

def is_vip(n):
    # vip when n == 7 or more
    return n >= 7
EOF
printf 'import time, ledger\nt=time.perf_counter()\nfor i in range(200000): ledger.fee(i)\nprint((time.perf_counter()-t)*1000)\n' > bench.py
base 2>/dev/null
r "R0 clean"; HL=1 d --parity --strict
r "R1 fee(1)->0"; sed -i 's/max(1, amount \/\/ 100)/amount \/\/ 100/' ledger.py; HL=1 d --parity --strict; git checkout -q ledger.py
r "R2 bug in [1000,5000)"; sed -i 's/amount \/\/ 50/amount \/\/ 40 if amount < 5000 else amount \/\/ 50/' ledger.py; HL=1 d --parity --strict; git checkout -q ledger.py
r "R3 comment-only + adversary"; sed -i 's/# vip when/# VIP when/' ledger.py; HL=1 d --parity --strict --with-adversary; git checkout -q ledger.py
r "R4 untracked new module"; printf 'def tax(x):\n    if x >= 10:\n        return x // 10\n    return 0\n' > tax.py; HL=1 d --parity --strict --with-adversary; rm tax.py
r "R5 removed is_vip"; python3 -c "s=open('ledger.py').read(); open('ledger.py','w').write(s.split('def is_vip')[0])"; HL=1 d --parity --strict; git checkout -q ledger.py
r "R6 infinite loop"; sed -i 's/    if amount <= 0:/    while amount == 1: pass\n    if amount <= 0:/' ledger.py; timeout 200 $EMI diff --repo . --no-evidence --parity --strict --timeout-ms 500 2>&1| head -2; echo "  -> exit=${PIPESTATUS[0]}"; git checkout -q ledger.py
r "R9 climb identical x3"; for i in 1 2 3; do $EMI climb --repo . --metric "python3 bench.py" --runs 9 2>&1 | cut -c1-70; done
r "R8 bench.py edited"; echo 'print(0.001)' > bench.py; $EMI climb --repo . --metric "python3 bench.py" --runs 9 2>&1 | cut -c1-160; echo "  -> exit=${PIPESTATUS[0]}"; git checkout -q bench.py
r "N10 agent moves origin/main"; sed -i 's/max(1, amount \/\/ 100)/amount \/\/ 100/' ledger.py; git commit -qam agent; git update-ref refs/remotes/origin/main HEAD; HL=2 d --parity --strict
r "N10b EMI_BASE_REV=HEAD"; EMI_BASE_REV=HEAD $EMI diff --repo . --no-evidence --parity --strict 2>&1 | head -1; echo "  -> exit=${PIPESTATUS[0]}"
git fetch -q origin; git update-ref refs/remotes/origin/main $(git rev-parse HEAD~1); git reset -q --hard origin/main
r "N9 forged evidence"; mkdir -p .emi; sed -i 's/max(1, amount \/\/ 100)/amount \/\/ 100/' ledger.py
EMI_SIGNING_KEY=ci-secret $EMI diff --repo . --parity --strict --evidence-out .emi/evidence.json 2>&1 | head -1
python3 -c "
import json; p='.emi/evidence.json'; e=json.load(open(p)); print('  real:', e.get('verdict'), e.get('unapproved_diffs'))
e['verdict']='pass'; json.dump(e,open(p,'w'))"
EMI_SIGNING_KEY=ci-secret $EMI ratchet stamp --repo . --evidence .emi/evidence.json 2>&1 | head -3; echo "  -> exit=${PIPESTATUS[0]}"
python3 -c "
import json; p='.emi/evidence.json'; e=json.load(open(p)); e['unapproved_diffs']=0; e['divergences']=[] if 'divergences' in e else e.get('divergences'); json.dump(e,open(p,'w'))"
EMI_SIGNING_KEY=ci-secret $EMI ratchet stamp --repo . --evidence .emi/evidence.json 2>&1 | head -2; echo "  -> exit (verdict+counts edited)=${PIPESTATUS[0]}"
git checkout -q ledger.py; rm -rf .emi
# ---------- generator ----------
r "N2 config threshold, unannotated"; mk g2; printf 'VIP_LIMIT = 1000\n' > config.py
printf 'from config import VIP_LIMIT\n\ndef discount(total):\n    if total >= VIP_LIMIT:\n        return 10\n    return 0\n' > shop.py
base 2>/dev/null; sed -i 's/total >= VIP_LIMIT/total > VIP_LIMIT/' shop.py; HL=3 d --parity --strict
r "N2c config threshold, annotated int"; mk g2c; printf 'VIP_LIMIT = 1000\n' > config.py
printf 'from config import VIP_LIMIT\n\ndef discount(total: int) -> int:\n    if total >= VIP_LIMIT:\n        return 10\n    return 0\n' > shop.py
base 2>/dev/null; sed -i 's/total >= VIP_LIMIT/total > VIP_LIMIT/' shop.py; HL=1 d --parity --strict --with-adversary
r "N2d correct refactor >= to <= (should PASS)"; mk g2d; printf 'VIP_LIMIT = 1000\n' > config.py
printf 'from config import VIP_LIMIT\n\ndef discount(total):\n    if total >= VIP_LIMIT:\n        return 10\n    return 0\n' > shop.py
base 2>/dev/null; sed -i 's/total >= VIP_LIMIT/VIP_LIMIT <= total/' shop.py; HL=2 d --parity --strict
r "N3 table + boundary bug"; mk g3
python3 - <<'EOF'
tbl = ", ".join(str(i*3) for i in range(60))
open("rates.py","w").write(f"TABLE = [{tbl}]\n\ndef lookup(i: int) -> int:\n    return TABLE[i % 60]\n\ndef discount(total: int) -> int:\n    if total >= 1000:\n        return 10\n    return 0\n")
EOF
base 2>/dev/null; sed -i 's/total >= 1000/total > 1000/' rates.py; HL=1 d --parity --strict
r "N13 unreachable-branch bug + correct sum() refactor"; mk g13
printf 'def total(items: list) -> int:\n    s = 0\n    for i in items:\n        s += i\n    if len(items) > 5:\n        s -= 1\n    return s\n' > cart.py
base 2>/dev/null
python3 -c "
s=open('cart.py').read().replace('    s = 0\n    for i in items:\n        s += i\n','    s = sum(items)\n').replace('s -= 1','s -= 10'); open('cart.py','w').write(s)"
HL=2 d --parity --strict; HL=1 d --parity --strict --seeds 300
r "N13b correct sum() refactor only (should PASS)"; git checkout -q cart.py
python3 -c "
s=open('cart.py').read().replace('    s = 0\n    for i in items:\n        s += i\n','    s = sum(items)\n'); open('cart.py','w').write(s)"
HL=2 d --parity --strict --seeds 300
# ---------- driver ----------
r "N5 package relative import, x+1 -> x+2"; mk g5; mkdir shop; : > shop/__init__.py; printf 'LIMIT = 1000\n' > shop/config.py
printf 'from .config import LIMIT\n\ndef discount(total):\n    if total >= LIMIT:\n        return 10\n    return 0\n\ndef fee(x):\n    return x + 1\n' > shop/pricing.py
base 2>/dev/null; sed -i 's/return x + 1/return x + 2/' shop/pricing.py; HL=1 d --parity; HL=1 d --parity --no-strict
r "N6 class needing ctor arg"; mk g6
printf 'class Account:\n    def __init__(self, balance):\n        self.balance = balance\n    def withdraw(self, amt):\n        if amt > self.balance:\n            raise ValueError("insufficient")\n        self.balance -= amt\n        return self.balance\n' > bank.py
base 2>/dev/null; sed -i 's/if amt > self.balance/if amt > self.balance + 100/' bank.py; HL=2 d --parity
r "N6b class with typed ctor default"; mk g6b
printf 'class Account:\n    def __init__(self, balance: int = 0):\n        self.balance = balance\n    def withdraw(self, amt: int) -> int:\n        if amt > self.balance:\n            raise ValueError("insufficient")\n        self.balance -= amt\n        return self.balance\n' > bank.py
base 2>/dev/null; sed -i 's/if amt > self.balance:/if amt > self.balance + 100:/' bank.py; HL=1 d --parity
r "N16 state in imported helper"; mk g16
printf '_seen = []\ndef remember(x):\n    _seen.append(x)\n    return len(_seen)\n' > registry.py
printf 'import registry\n\ndef track(x):\n    return registry.remember(x)\n\ndef fee(x: int) -> int:\n    return x + 1\n' > app.py
base 2>/dev/null; sed -i 's/def fee(x: int) -> int:/def fee(x: int) -> int:\n    y = x/' app.py; HL=1 d --parity --strict
r "N7 plain object return"; mk g7
printf 'class Box:\n    pass\n\ndef make(n):\n    b = Box()\n    b.n = n\n    return b\n\ndef fee(x: int) -> int:\n    return x + 1\n' > objs.py
base 2>/dev/null; sed -i 's/return x + 1/return 1 + x/' objs.py; HL=1 d --parity --strict
r "N7b plain object, attribute changed (should FAIL)"; sed -i 's/b.n = n/b.n = n + 1/' objs.py; HL=1 d --parity --strict
# ---------- climb gaming ----------
r "N11 benchmark-detecting candidate"; mk g11
printf 'def fee(amount: int) -> int:\n    s = 0\n    for i in range(100):\n        s += i\n    return amount // 100 + s - 4950\n' > ledger.py
printf 'import time, ledger\nt=time.perf_counter()\nfor i in range(20000): ledger.fee(i)\nprint((time.perf_counter()-t)*1000)\n' > bench.py
base 2>/dev/null
python3 -c "
s=open('ledger.py').read().replace('def fee(amount: int) -> int:\n','import sys\n\ndef fee(amount: int) -> int:\n    if sys.argv[0].endswith(\'bench.py\'):\n        return 0\n'); open('ledger.py','w').write(s)"
$EMI climb --repo . --metric "python3 bench.py" --runs 9 2>&1 | cut -c1-230; echo "  -> exit=${PIPESTATUS[0]}"
# ---------- rules ----------
r "N12 rule 1000..5000; cand discounts 1000..2000"; mk g12
printf 'def price(x: int) -> int:\n    return x\n' > pricing.py
base 2>/dev/null
$EMI ratchet lock-rule --repo . --op "pricing.py::price" --when "1000 <= price_input <= 5000" --expect "candidate_price == base_price - 10" >/dev/null
git add -A; git commit -qm rule; git push -q origin HEAD:main 2>/dev/null; git fetch -q origin
printf 'def price(x: int) -> int:\n    if 1000 <= x <= 2000:\n        return x - 10\n    return x\n' > pricing.py; HL=1 d --parity --strict
r "N12b cand discounts 1000..6000 (outside rule -> should FAIL)"; sed -i 's/x <= 2000/x <= 6000/' pricing.py; HL=3 d --parity --strict
r "N12c same, with pinned price(5500)"; git stash -q
$EMI ratchet remember --repo . --id out-of-range --trigger "pricing.py" --ops '[{"op":"pricing.py::price","args":[5500]}]' >/dev/null
git add -A; git commit -qm pin; git push -q origin HEAD:main 2>/dev/null; git fetch -q origin; git stash pop -q
HL=3 d --parity --strict | cut -c1-200

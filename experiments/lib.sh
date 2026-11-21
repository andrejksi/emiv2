EMI="${EMI:-emi}"
# mk REPO: fresh repo with bare origin; files written by caller before `base`
mk() { rm -rf /tmp/$1 /tmp/$1.git; git init -q --bare /tmp/$1.git; mkdir /tmp/$1; cd /tmp/$1; git init -q; git config user.email a@b; git config user.name t; git remote add origin /tmp/$1.git; }
base() { git add -A; git commit -qm base; git push -q origin HEAD:main; git fetch -q origin; }
d() { $EMI diff --repo . --no-evidence "$@" 2>&1 | head -${HL:-3}; echo "  -> exit=${PIPESTATUS[0]}"; }

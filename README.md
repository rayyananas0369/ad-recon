# adscope — Active Directory Recon Toolkit

End-to-end AD reconnaissance in a single script. Discovers live hosts on a
subnet, identifies Domain Controllers, performs AS-REP roasting, cracks
hashes with John, enumerates users/groups, and collects BloodHound data.

## Features

- **Subnet sweep** — `fping` + ARP cache correlation to find live hosts
- **DC discovery** — port-signature scan (88, 389, 445)
- **RootDSE recon** — extracts naming context, checks SMB null sessions
- **AS-REP roasting** — casing sweep (lower/title/upper) with `impacket-GetNPUsers`
- **Hash cracking** — automated John the Ripper workflow
- **LDAP enumeration** — users, groups, high-value group membership
- **BloodHound collection** — DCOnly ZIP, FQDN-aware with automatic DNS swap

## Requirements

| Tool | Purpose | Install |
|---|---|---|
| `fping` | Host sweep | `apt install fping` |
| `nmap` | Port scan / DC discovery | `apt install nmap` |
| `ldap-utils` | RootDSE / LDAP queries | `apt install ldap-utils` |
| `impacket` | AS-REP roasting | `pip install impacket` |
| `john` | Hash cracking | `apt install john` |
| `netexec` (nxc) | SMB checks | `pip install netexec` |
| `bloodhound` | AD graph collection | `pip install bloodhound` |

## Usage

```bash
chmod +x adscript.sh

# Interactive interface prompt
./adscript.sh -w username.txt

# Non-interactive with specific interface
./adscript.sh -i eth0 -w username.txt

# Full options
./adscript.sh -i eth0 -w username.txt -c /usr/share/wordlists/rockyou.txt

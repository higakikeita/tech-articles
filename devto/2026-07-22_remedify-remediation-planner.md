---
title: "remedify: turn a vulnerability scan into the exact commands to fix it — deterministic, no AI guessing"
published: false
tags: security, devops, opensource, linux
canonical_url:
---

> Draft for dev.to (English-first, global audience). `published: false` — review then publish. JP version on Qiita: https://qiita.com/keitah/items/ae499386016fa87bfef8 (different language, no canonical conflict).

Every vulnerability scanner ends the same way — with a finding, and a question it doesn't answer.

```
libssl3  3.0.2-0ubuntu1.15  →  CVE-2024-6119 (HIGH), fixed in 3.0.2-0ubuntu1.18
```

Great. Now: **what exactly do I run on this host to fix it?**

- On Ubuntu? `apt-get install --only-upgrade libssl3=3.0.2-0ubuntu1.18`
- On RHEL? a `dnf` line — and the fixed version won't match upstream, because it's a backport
- On Alpine? `apk`
- Is a **reboot** needed (kernel)? a **service restart** (OpenSSL)?

That last mile is out of scope for the scanner, so a human looks it up in vendor docs, every single time. I built a CLI to close it.

## remedify

```bash
pip install remedify
trivy image --format json -o scan.json myapp:1.0
remedify scan.json
```

Feed it scanner output (Trivy / Grype / Sysdig / OSV — format auto-detected) and it emits an **executable remediation plan**: the exact per-OS commands, with the version pinned.

```markdown
## libssl3  `HIGH`
- Installed: 3.0.2-0ubuntu1.15  →  Fix: 3.0.2-0ubuntu1.18
- CVEs: CVE-2024-5535, CVE-2024-6119
- Vendor backport (Ubuntu): the fixed version is a distro backport — it will
  not match the upstream version number.

    apt-get install --only-upgrade libssl3=3.0.2-0ubuntu1.18

- ⚠️ Restart services linked against OpenSSL (nginx, sshd, ...).
- Advisory: https://ubuntu.com/security/notices/USN-6986-1
```

Output in four shapes: `markdown` (review/tickets), `shell` (run it), `json` (pipe to other tools), `ansible` (fleet rollout, with a reboot task guarded by a variable).

## Why it exists (not just what it does)

There are plenty of tools that *detect*. What teams struggle with is *how to fix* — and a few things make that genuinely annoying, which remedify handles:

- **Backports** (Ubuntu/RHEL): "I upgraded but the scanner is still red / what is `0ubuntu1.18`?" → remedify attaches the explanation and the vendor advisory link every time.
- **Command consolidation**: one CVE fans out into many binary packages (e.g. `e2fsprogs`, `libcom-err2`, `libext2fs2`…). remedify collapses them into one command. Seven openssh packages → one line.
- **"No fix available" is shown, not dropped**: findings with no fix land in their own section with vendor status (`will_not_fix` / EOL) — so nothing silently disappears from the report. Usable as an audit trail.
- **Language packages aren't OS packages**: a vulnerable Go binary or npm dep can't be `apt`-fixed, so remedify emits the rebuild-and-redeploy path instead.
- **Fleet view**: process many workloads and it tells you "fixing `libc6` once clears 3 images" — so you can prioritize by blast radius.

## Deterministic. The AI doesn't invent the fix.

This is the design line I care about most: remedify is **deterministic** — same scan, same commands. It does not ask an LLM to make up a fix. The tool computes the plan; if you want an AI in the loop, its job is to *explain*, not to decide. For a security tool that outputs privileged commands, "the tool calculated this" beats "the model suggested this."

Non-goal: remedify never auto-applies anything. It plans; you (or your CI) decide.

## Complementary to Copacetic, not competing

If you know [Copacetic (copa)](https://github.com/project-copacetic/copacetic): it patches **container images** directly from scan results. remedify covers the **host / VM OS** side (apt/dnf/apk/zypper + backport handling) and language packages. Two halves:

- **containers → copa** (patch the image)
- **hosts → remedify** (the last-mile commands + advisories)

They compose rather than overlap.

## Try it

```bash
pip install remedify
remedify your-scan.json
```

Repo: https://github.com/higakikeita/remedify — alpha, single-file Python, zero dependencies, Apache-2.0. Throw a messy scanner report at it; a broken report is the most useful bug you can file.

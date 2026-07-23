---
title: "detect → understand → fix: three small OSS tools, one idea about security findings"
published: false
tags: security, devops, opensource, kubernetes
canonical_url:
---

> Draft for dev.to (English-first). `published: false` — review then publish. This is the "thesis" piece that ties three tools together; publish after the individual whyq/remedify posts so it can link them.

Security tooling is very good at one thing and quietly bad at another.

It is **excellent at telling you *what* is wrong**: this package has this CVE, this syscall fired this Falco rule, this Terraform plan will replace that security group. It is **bad at the next two questions a human actually has**:

- *why does this matter, and what do I check first?*
- *what exactly do I run to fix it?*

Those two gaps get filled by hand, every day, by someone reading vendor docs with 40 tabs open. I've been building three small OSS tools — each does one job — around the shape of that gap:

**detect → understand → fix**

None of them is trying to be a platform. The interesting part is the seam between them.

## detect — surface that something changed

[tfdrift-falco](https://github.com/higakikeita/tfdrift-falco) watches for infrastructure drift: someone changes a security group in the AWS console, and it catches the CloudTrail event in real time — and, crucially, tells you *who* did it (including SSO / assumed-role identities) and *when*. It's the "the moment reality diverged from your Terraform" signal.

Honest status: it's alpha, focused on AWS/GCP, and I've been aggressively pruning its claims down to what actually works — because a detector that silently misses drift is worse than no detector. (That pruning is its own story.)

## understand — turn a raw finding into human language

[whyq](https://github.com/higakikeita/whyq) is the middle layer. Hand it a file — a Trivy scan, a Falco alert, a Terraform plan, a Sysdig event, 10 tools in total — and it returns the same six fields for each finding: *what / why / severity / what to check / how to fix / reference*.

No cluster to connect to, no agent, no SaaS. Just the artifact you already have. One grammar across very different tools, so "which tool's output am I reading?" stops being overhead.

```bash
pip install whyq
whyq explain scan.json
```

## fix — the exact commands, deterministically

[remedify](https://github.com/higakikeita/remedify) closes the loop for OS packages: it turns "fixed in 3.0.2-0ubuntu1.18" into the actual `apt`/`dnf`/`apk` line, handles distro backports, tells you if a reboot or service restart is needed, and is honest about "no fix available." Deterministic — the tool computes the command; it doesn't ask an LLM to invent one.

```bash
pip install remedify
remedify scan.json
```

## The seam is the point

Each tool does one job and hands off through plain files:

- whyq's machine-readable output is shaped so remedify can eat it.
- whyq deliberately does **not** reimplement fix logic — for OS-package vulnerabilities it defers to remedify.
- For container images specifically, the fix half is better served by [Copacetic](https://github.com/project-copacetic/copacetic); remedify covers the host/OS side. They compose, not compete.

The through-line I care about is **contextualizing a detection** — moving from "an alert fired" to "here's what it means and what to do," with the deterministic parts kept deterministic and the AI (optional, off by default) only ever explaining, never deciding.

## Why three tools instead of one

Because each stays auditable and swappable. You can use whyq without the other two. You can pipe your existing scanner into remedify and ignore tfdrift entirely. The composition is a convenience, not a lock-in — which is the opposite of how most "platforms" in this space work.

All three are early and MIT-licensed. If you try one and it does something dumb, an issue with the (sanitized) input is the most useful thing you can send.

- detect: https://github.com/higakikeita/tfdrift-falco
- understand: https://github.com/higakikeita/whyq
- fix: https://github.com/higakikeita/remedify

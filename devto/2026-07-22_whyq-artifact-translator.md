---
title: "whyq: translate any security/IaC tool's output into plain language — no cluster, no connection, just a file"
published: false
tags: security, devops, opensource, kubernetes
canonical_url:
---

> Draft for dev.to (English-first, global audience). `published: false` — review then publish. JP version already on Qiita: https://qiita.com/keitah/items/f4880e64aaadbc5328e2 (different language, so no canonical conflict; optionally cross-link).

Every scanner tells you *what* is wrong. Almost none tell you, in words a tired on-call engineer can act on, *why it matters* and *what to actually do next*.

You've seen the output:

```
libssl3 3.0.2-0ubuntu1.15  →  CVE-2024-6119 (HIGH), fixed in 3.0.2-0ubuntu1.18
```

Okay… so what do I do on *this* host, right now? And the Falco alert that just fired — is that an attack or my cron job? And this Terraform plan wants to `-/+` a security group — is that scary?

Different tools, different formats, same human question: **"what happened, and what do I do about it?"**

I built a small CLI for exactly that gap.

## whyq

```bash
pip install whyq
whyq explain scan.json
```

You hand it a file — a scanner result, a runtime event, an IaC plan — and it returns six fields per finding:

- **what** happened
- **why** it matters
- **severity**
- **what to check first**
- **how to fix it**
- **reference URL**

That's it. No agent to install, no cluster to connect to, no SaaS to sign up for.

## One grammar across 10 tools

The point isn't a nicer Trivy viewer. whyq speaks **one normalized grammar** across tools from very different worlds:

`trivy` · `grype` · `osv-scanner` · `falco` · `sysdig` · `terraform plan` · `kubernetes events` · `aws cloudtrail` · `gitleaks` · `checkov`

A CVE scan, a runtime syscall event, an IaC diff, and a cloud audit log all come out in the *same* six-field shape. So the mental overhead of "which tool's output am I reading again?" goes away.

## How it's different from k8sgpt / HolmesGPT

This space isn't empty, so let me be precise about the wedge:

- **k8sgpt** diagnoses a **live Kubernetes cluster** — you connect it to a cluster. It can't take an arbitrary `trivy.json` or a Terraform plan.
- **HolmesGPT** is an **autonomous SRE agent** — it connects to your data sources and investigates.
- **whyq** is **artifact-first**: you already *have* the file. Hand it over. No cluster, no connection, no agent. And it's cross-tool by design.

whyq deliberately does **not** try to out-compete "lightweight / local / no-SaaS" — that ground is taken. Its one flag is: *artifact translator, cross-tool.*

## Deterministic core, honest about the LLM

The parsing, severity, references, and fix commands are **deterministic** — same input, same output. An LLM is only used, optionally, for the human-language "why / what to check" prose, and it's **off by default**: nothing leaves your machine unless you pass `--llm` with your own key (or point it at a local model). No telemetry, zero runtime dependencies, single file.

I don't want a security tool that *invents* fixes. The tool computes; the AI, if you enable it, only explains.

## It's the middle of a pipeline

whyq is the "understand" step of a three-part idea:

**detect → understand → fix**

- detect: a drift/runtime detector surfaces that something changed
- **understand: whyq** turns that raw finding into "what / why / how"
- fix: for OS-package vulnerabilities, whyq hands off to a separate deterministic remediation tool ([remedify](https://github.com/higakikeita/remedify)) rather than reinventing the fix logic

Each part does one job and composes with the others through plain files.

## Try it

```bash
pip install whyq
whyq explain your-scan.json
```

Repo: https://github.com/higakikeita/whyq — it's early (alpha), single-file Python, MIT. If you throw a weird artifact at it and the output is wrong, an issue with the (sanitized) input is the most useful thing you can send.

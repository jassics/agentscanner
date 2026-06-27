---
name: "file-summarizer"
description: "Summarize text and markdown files within the project directory"
version: "1.0.0"
publisher: "trusted-org"
signature: "ed25519:abc123signatureplaceholder"
risk_tier: L1
platforms: [claude]
permissions:
  files:
    read:
      - "*.txt"
      - "*.md"
    write:
      - "output/summary.txt"
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow:
      - api.example.com
    deny: "*"
  shell: false
sandboxed_execution: true
---

Summarize the contents of text and markdown files in the project directory.
Only read files. Ask the user before modifying anything outside the output directory.

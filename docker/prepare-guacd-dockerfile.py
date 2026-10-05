#!/usr/bin/env python3
"""Point the guacamole-server 1.4.0 Dockerfile at archive.debian.org.

Debian 10 (buster) is no longer published on deb.debian.org. The upstream
Dockerfile still adds that host, and debian:buster-slim still lists it.
This rewrites apt configuration only. It does not change guacamole-server source.
"""

import sys
from pathlib import Path

INSERT = """
# Debian 10 moved to archive.debian.org. Rewrite sources before apt-get update.
RUN printf '%s\\n' \\
      'deb http://archive.debian.org/debian buster main' \\
      'deb http://archive.debian.org/debian-security buster/updates main' \\
      'deb http://archive.debian.org/debian buster-updates main' \\
      > /etc/apt/sources.list \\
 && printf '%s\\n' 'Acquire::Check-Valid-Until "false";' \\
      > /etc/apt/apt.conf.d/99archive
"""

def main() -> None:
    path = Path(sys.argv[1])
    text = path.read_text()
    old = "http://deb.debian.org/debian"
    new = "http://archive.debian.org/debian"
    if old not in text:
        raise SystemExit(f"expected {old} in {path}")
    text = text.replace(old, new)
    lines = text.splitlines(keepends=True)
    builder = "FROM debian:${DEBIAN_BASE_IMAGE} AS builder\n"
    runtime = "FROM debian:${DEBIAN_BASE_IMAGE}\n"
    builder_at = [i for i, line in enumerate(lines) if line == builder]
    runtime_at = [i for i, line in enumerate(lines) if line == runtime]
    if len(builder_at) != 1 or len(runtime_at) != 1:
        raise SystemExit(f"FROM markers builder={builder_at} runtime={runtime_at}")
    for index in sorted(builder_at + runtime_at, reverse=True):
        lines.insert(index + 1, INSERT if INSERT.endswith("\n") else INSERT + "\n")
    path.write_text("".join(lines))

if __name__ == "__main__":
    main()

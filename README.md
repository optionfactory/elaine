# repospect

An internal CLI tool for inspecting and gathering data from all GitHub repositories in an organization.

## How It Works

1. **Sync & Cache:** fetches repository metadata from the GitHub API and caches source archives (`.tar.gz`) locally.
2. **Scan:** decompresses cached tarballs in memory across worker goroutines to check for specific files or configurations (such as Ansible files, Dockerfiles, and deployment configs) in a single pass.

## Prerequisites

* A GitHub token with read access to the organization set in your environment (`GITHUB_TOKEN`) or retrieved via `gh auth token`

## Installation

```bash
curl -sSL \
  https://github.com/optionfactory/repospect/releases/latest/download/repospect-linux-amd64-musl \
  | sudo tee /usr/local/bin/repospect > /dev/null \
  && sudo chmod +x /usr/local/bin/repospect
```

### Sync Repositories
Download or update local repository tarballs in `./cache`:
```bash
repospect --organization YOUR_ORG --cache-dir DIR sync
```

### Generate Stats
Scan cached repositories and output JSON:
```bash
repospect --organization YOUR_ORG --cache-dir DIR stats
```

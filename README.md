# Elaine - governor of Melee Island.

A CLI tool for aggregating and inspecting governance manifests and dependency vulnerabilities across an organization's GitHub repositories.

> *"That's the second biggest attack surface I've ever seen!"*
>
> — Elaine, sizing up your dependency tree.

## Prerequisites

* A GitHub personal access token with read permissions for the target organization. This can be provided via the `GITHUB_TOKEN` or `GH_TOKEN` environment variables, or by having an active `gh auth token` session.
* An `elaine.conf.json` configuration file in the working directory.
* The ecosystem tools the scanners invoke: `mvn`, `npm`, `go`, and `cargo` with [`cargo-outdated`](https://github.com/kbknapp/cargo-outdated) (only needed for repositories using that ecosystem).

## Installation

```bash
curl -sSL https://github.com/optionfactory/elaine/releases/latest/download/elaine-linux-amd64-musl \
  | sudo tee /usr/local/bin/elaine > /dev/null \
  && sudo chmod +x /usr/local/bin/elaine
```

## Configuration

Create an `elaine.conf.json` file in the directory where you run the tool:

```json
{
  "organization": "your-organization",
  "data_dir": "data",
  "address": "127.0.0.1",
  "port": 8000,
  "google_auth": {
    "client_id": "{{ID}}.apps.googleusercontent.com",
    "hosted_domain": "your-organization.com"
  }
}
```

All fields except `organization` are optional: `data_dir` defaults to `data`, the server binds to `127.0.0.1:8000`, `github_token` can be set here or resolved from the environment, and omitting `google_auth` serves the dashboard without authentication.

## Usage

```bash
elaine sync        # fetch repository metadata and cache .tar.gz archives from GitHub
elaine scan        # unpack and audit the cached repositories
elaine serve       # serve the dashboard and stats data over HTTP
elaine bootstrap   # sync + scan + serve in one go
elaine init        # create a stub elaine.yaml manifest in the current folder
elaine clean-stats        # remove per-repository scan data and the aggregated stats file
elaine clean-repositories # remove cached repository metadata and archives
```

The three main phases in detail:

1. **Sync:** Fetch repository metadata from the GitHub API and cache source archives (`.tar.gz`) locally.

2. **Scan:** Unpack the cached tarballs to temporary directories across concurrent workers. It scans for specific files, dependencies, and configurations (e.g., Ansible, Docker, legopfa, pinch) in a single pass, then runs per-ecosystem checks: known vulnerabilities via the [OSV](https://osv.dev) API and outdated dependencies via the ecosystem's own tooling.

   > *"Well, well, well, `Log4Shell`. You do turn up in the strangest of places."*
   >
   > — Elaine, reviewing your outdated dependencies.

   When a check fails (tool missing, unparseable lockfile, OSV unreachable), the failure is recorded per repo and scanner, and the command's full output is kept in `data/stats/logs/<repo>/<scanner>.log`. The dashboard's Security page lists all failures and lets you inspect the logs.

3. **Serve:** Launch the embedded Axum web server to view the aggregated statistics in a browser dashboard. Pass `--dev` to serve frontend assets from `./src/frontend/` instead of the embedded binary.

## Repository Manifests

### Governance & Compliance (`elaine.yaml`)

Each repository can declare an `elaine.yaml` governance manifest at its root. Elaine audits it and surfaces the metadata (service tier, lifecycle, project type, regulatory applicability) in the dashboard, where it can be used to filter projects. Repositories without a valid manifest show up as *without manifest*:

> *"Less talking, more eviscerating, 'sweetie.'"*
>
> — Elaine, on repositories with no `elaine.yaml`.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/optionfactory/elaine/refs/heads/master/schema/elaine-v1.schema.json
schema_version: 1
name: "my-service"
type: service                # library | service | tool | infrastructure | documentation | playground
lifecycle: active            # active | maintenance | unmaintained | deprecated | end-of-life | prototype
tier: tier2                  # tier1 (24/7 SLA) -> tier4 (experimental)
stewards:
  - "mario.rossi@example.com"
sensitivity:
  - pii
compliance:
  dora: non-critical         # EU Digital Operational Resilience Act
  cra: default               # EU Cyber Resilience Act
  nis2: important-entity     # EU NIS2 Directive
  ai_act: out-of-scope       # EU AI Act
  gdpr: controller           # GDPR processing role
  data_residency: eu         # EU | eea | us | global | not-applicable | pending-assessment
  ads: internal              # Italian Garante AdS responsibility
environments:
  - name: "production"
    type: production
    platform: cloud
    ingress: restricted-vpn
    dns: managed
    certificates: managed-acme-dns01
    domains:
      - api.example.com
```

Only `schema_version` and `name` are required; every other field is optional. Compliance fields left as `pending-assessment` (or ads `pending-nomination`) count as non-compliant in the dashboard filters:

> *"Guybrush, this is important. Are you listening to me? This is IMPORTANT!"*
>
> — Elaine, on compliance fields still set to `pending-assessment`.

Adding the comment above as the first line of the file enables autocompletion and validation in IDEs with YAML language server support. Run `elaine init` to generate a stub.

### Process Supervision (`pinch.yaml`)

Elaine also detects [`pinch.yaml`](https://github.com/optionfactory/pinch) manifests (the process supervisor's workflow manifest) and deduces the Docker container images declared by `type: "docker"` processes, reporting them as container dependencies.

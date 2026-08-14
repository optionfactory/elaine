# Elaine - governor of Melee Island.

A CLI tool for aggregating and inspecting metadata, governance manifests, SBOMs, and dependency vulnerabilities across an organization's GitHub repositories.

> *"That's the second biggest attack surface I've ever seen!"*
>
> — Elaine, sizing up your dependency tree.

## Prerequisites

* A GitHub personal access token with read permissions for the target organization. This can be provided via the `GITHUB_TOKEN` or `GH_TOKEN` environment variables, or by having an active `gh auth token` session.
* An `elaine.json` configuration file in the working directory.

## Installation

```bash
curl -sSL https://github.com/optionfactory/elaine/releases/latest/download/elaine-linux-amd64-musl \
  | sudo tee /usr/local/bin/elaine > /dev/null \
  && sudo chmod +x /usr/local/bin/elaine
```

## Configuration

Create an `elaine.json` file in the directory where you run the tool:

```json
{
  "organization": "your-organization",
  "data_dir": "data",
  "google_auth": {
    "client_id": "{{ID}}.apps.googleusercontent.com",
    "hosted_domain": "your-organization.com"
  }
}
```

## Usage

The tool operates in three main phases based on the local `elaine.json` configuration:

1. **Sync:** Fetch repository metadata from the GitHub API and cache source archives (`.tar.gz`) locally.
   ```bash
   elaine sync
   ```

2. **Scan:** Decompress the cached tarballs in memory across concurrent asynchronous workers. It scans for specific files, dependencies, and configurations (e.g., Ansible, Docker, Maven) in a single pass, collecting known vulnerabilities via the [OSV](https://osv.dev) API.
   ```bash
   elaine scan
   ```

   > *"You fight like a dairy farmer."* 
   >
   > — Elaine, reviewing your outdated dependencies.

3. **Serve:** Launch the embedded Axum web server to view the aggregated statistics in a local browser dashboard. 
   ```bash
   elaine serve
   ```

## Repository Manifests

### Governance & Compliance (`elaine.yaml`)

Each repository can declare an `elaine.yaml` governance manifest at its root. Elaine audits it and surfaces the metadata (service tier, lifecycle, project type, regulatory applicability) in the dashboard, where it can be used to filter projects. Repositories without a valid manifest show up as *unaudited*:

> *"Let's face it, Guybrush. You're a natural born failure."* 
>
> — Elaine, on repositories with no `elaine.yaml`.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/optionfactory/elaine/refs/heads/master/schema/elaine-v1.schema.json
schema_version: 1
name: "my-service"
type: service                # library | service | tool | infrastructure | documentation
lifecycle: active            # active | maintenance | deprecated | end-of-life | prototype
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

Only `schema_version` and `name` are required; every other field is optional. Compliance fields left as `pending-assessment` count as non-compliant in the dashboard filters:

> *"Guybrush, this is important. Are you listening to me? This is IMPORTANT!"*
>
> — Elaine, on compliance fields still set to `pending-assessment`.

Adding the comment above as the first line of the file enables autocompletion and validation in IDEs with YAML language server support.

### Process Supervision (`pinch.yaml`)

Elaine also detects [`pinch.yaml`](https://github.com/optionfactory/pinch) manifests (the process supervisor's workflow manifest) and deduces the Docker container images declared by `type: "docker"` processes, reporting them as container dependencies.

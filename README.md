# repospect

A CLI tool for aggregating and inspecting metadata, DevSecOps configurations, and SBOMs across an organization's GitHub repositories.

## Prerequisites

* A GitHub personal access token with read permissions for the target organization. This can be provided via the `GITHUB_TOKEN` or `GH_TOKEN` environment variables, or by having an active `gh auth token` session.
* A `repospect.json` configuration file in the working directory.

## Installation

```bash
curl -sSL https://github.com/optionfactory/repospect/releases/latest/download/repospect-linux-amd64-musl \
  | sudo tee /usr/local/bin/repospect > /dev/null \
  && sudo chmod +x /usr/local/bin/repospect
```

## Configuration

Create a `repospect.json` file in the directory where you run the tool:

```json
{
  "organization": "optionfactory",
  "data_dir": "data",
  "google_auth": {
    "client_id": "{{ID}}.apps.googleusercontent.com",
    "hosted_domain": "optionfactory.net"
  }
}
```

## Usage

The tool operates in three main phases based on the local `repospect.json` configuration:

1. **Sync:** Fetch repository metadata from the GitHub API and cache source archives (`.tar.gz`) locally.
   ```bash
   repospect sync
   ```

2. **Scan:** Decompress the cached tarballs in memory across concurrent asynchronous workers. It scans for specific files, dependencies, and configurations (e.g., Ansible, Docker, Maven) in a single pass.
   ```bash
   repospect scan
   ```

3. **Serve:** Launch the embedded Axum web server to view the aggregated statistics in a local browser dashboard. 
   ```bash
   repospect serve
   ```

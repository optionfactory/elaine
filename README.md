# Elaine - governor of Melee Island.

A CLI tool for aggregating and inspecting governance manifests and dependency vulnerabilities across an organization's GitHub repositories.

> *"That's the second biggest attack surface I've ever seen!"*
>
> — Elaine, sizing up your dependency tree.

## Prerequisites

* A GitHub personal access token with read permissions for the target organization. This can be provided via the `GITHUB_TOKEN` or `GH_TOKEN` environment variables, or by having an active `gh auth token` session.
* An `elaine.conf.json` configuration file in the working directory.
* The ecosystem tools the scanners invoke: `mvn`, `npm`, `go`, and `cargo` with [`cargo-outdated`](https://github.com/kbknapp/cargo-outdated) (only needed for repositories using that ecosystem).
* For the container images: `docker` with `buildx`, and [`grype`](https://github.com/anchore/grype), which keeps its own vulnerability database (a few hundred MB, updated at every scan). Without them every image shows as failed, and the rest of the scan goes on.

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
  "login": {
    "client_id": "{{ID}}.apps.googleusercontent.com",
    "client_secret": "{{SECRET}}",
    "public_url": "https://elaine.your-organization.com",
    "domain": "your-organization.com"
  }
}
```

All fields except `organization` are optional: `data_dir` defaults to `data`, the server binds to `127.0.0.1:8000`, `github_token` can be set here or resolved from the environment, and omitting `login` serves the dashboard without authentication. Within `login` every field is required, `domain` included: without it any Google account would sign in. The file holds the tokens and the login secret: elaine refuses to start when every user of the machine can read it (its group may). What it writes in `data_dir` (the scan data, the images, the logs) is readable only by its own user: files 0600, directories 0700; `data_dir` itself is left as the deployment sets it. Unknown fields are refused.

With `login`, the whole dashboard (pages, assets and API) requires a Google login of `domain`: the authorization code flow with PKCE, then a session cookie valid for 12 hours, signed with a key generated at every start (a restart signs everyone out). Only `/favicon.svg` and the pushes to `/api/snapshot` stay public. The OAuth client needs one authorized redirect URI, `<public_url>/oidc/callback`; `/logout` signs out.

### Scanning on a different machine

`serve` only needs the scan results, so the dashboard can run on a server while `sync` and `scan` run on another machine (the one holding the GitHub token and the ecosystem tools) that pushes the results to it.

On the server, set the token that pushes must present:

```json
{
  "organization": "your-organization",
  "push_token": "{{A LONG RANDOM STRING}}"
}
```

On the scanning machine, point `remote` at the server:

```json
{
  "organization": "your-organization",
  "remote": {
    "url": "https://elaine.your-organization.com",
    "token": "{{THE SAME STRING}}"
  }
}
```

With `remote` configured, `scan` pushes its results at the end, even when some repositories failed; `elaine push` sends the last results again without rescanning. Each push replaces everything the server shows. The token travels in an HTTP header, so put the server behind a reverse proxy that terminates TLS. Without `push_token`, the server refuses every push. The token is checked before the body is read; a push may be at most 16 MB gzipped and 256 MB unzipped (a real one of a few hundred repositories is about 1 MB and 10 MB), and each repository's `html_url` must be under `https://github.com/<organization>/`, since the pages and the mails link to it. Refused pushes are logged, without the token.

### Mail on new vulnerabilities

With `alerts`, the server mails the vulnerabilities each push brings that the previous one did not have:

```json
{
  "alerts": {
    "smtp_host": "smtp-relay.example.com",
    "smtp_port": 587,
    "from": "elaine-noreply@your-organization.com",
    "to": "admins@your-organization.com"
  }
}
```

The relay must take mail without credentials (by the address of the server, for example). STARTTLS is required, except
on a loopback address; `smtp_port` defaults to 587, and the domain of `from` is the name elaine gives in `EHLO`.

A vulnerability is new once per repository, artifact and advisory: the same advisory at another version of the
artifact is not. The first push, or the first after the data was lost, sends nothing. A repository counts only when both
pushes scanned it for vulnerabilities, so a scan that failed once does not make all its vulnerabilities new at the
next; a repository that shows up for the first time counts whole. Archived repositories are left out. The push
answers without waiting for the mail; a mail that fails is only logged.

The container images follow the same rules, with the image compared without its tag (moving a repository to a newer tag
does not announce again what the newer tag still has), and only their fixable high and critical vulnerabilities are
mailed. The first push that scanned images sends nothing for them. A tag the previous push could not scan (Docker Hub
rate limits the inspections) sends nothing either, rather than being compared with the other tags of its image.

### Container images

After the repositories, `scan` looks at every image the live repositories run (from their pinch configurations and Ansible playbooks), once
per image: it reads the SBOM the registry publishes for it with `docker buildx imagetools inspect` (the image is not
pulled; for a multi-platform image, the `linux/amd64` one) and runs `grype --only-fixed` on it. Only the
vulnerabilities that already have a fix are kept: the ones a newer image removes. An image whose registry publishes no
SBOM is shown as such and not scanned. This runs at every scan, also when no repository changed, since new advisories
hit images that did not change. The results go to `images.json` next to `stats.json`, and travel in the push.

The dashboard shows them apart from the vulnerabilities of the dependencies: on each repository, the images it runs
with what their scan found; on the security page, a section with every image and its vulnerabilities, and in the
ranking of the repositories a column with the fixable high and critical vulnerabilities of their images, which does not
change the order.

## Usage

```bash
elaine sync        # fetch repository metadata and cache .tar.gz archives from GitHub
elaine scan        # unpack and audit the cached repositories
elaine serve       # serve the dashboard and stats data over HTTP
elaine push        # send the scan results to the configured remote server
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

   A repository that did not change since its last scan, and whose checks all passed, is not unpacked again. Its dependencies are still checked against OSV at every scan, in one batch for all such repositories, from the list each scanner recorded at the last full scan (`data/stats/dependencies/<repo>.json`, kept on the scanning machine and never pushed): new advisories hit dependencies that did not change. For Maven the list comes from `anarchitect-dependencies.json`, written by anarchitect since 1.17; with an earlier anarchitect, the Maven vulnerabilities of an unchanged repository stay as the last full scan found them. If OSV cannot be reached, the repositories keep the vulnerabilities they had.

3. **Serve:** Launch the embedded Axum web server to view the aggregated statistics in a browser dashboard. Pass `--dev` to serve frontend assets from `./src/frontend/` instead of the embedded binary.

   Besides the dashboard and the governance, security and inventory pages, each repository has its page, `repository.html#<name>`: what GitHub says of it, what its manifest declares, its compliance per framework, the vulnerabilities of its dependencies and of the images it runs, its outdated dependencies and its scanner failures with their logs. Each steward has theirs, `steward.html#<steward>`: their live repositories and the compliance frameworks still pending on them. A steward written as an email `first.last@domain` is the same person as `First Last`, and case does not count. Both pages read the API, behind the login like the rest:

   - `GET /api/projects/{name}`: the repository as `/api/projects` lists it, plus `pending_frameworks` (the compliance frameworks still to assess) and `image_vulnerabilities` (the fixable vulnerabilities of each scanned image it runs, by image); 404 when there is no such repository.
   - `GET /api/stewards/{name}`: `steward` (the name as the page shows it), `written_as` (the spellings found in the manifests), `repositories` (the live ones naming the steward: name, type, tier, lifecycle, counts of vulnerabilities and outdated dependencies, `null` when not checked, last push), `pending` (each framework still pending, with its repositories) and `without_compliance` (the repositories whose manifest has no compliance block); 404 when no repository names the steward.

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

### Ansible playbooks

In a repository with an `ansible.cfg`, Elaine reads the playbooks and task files under its directory (the YAML files
that are a list: a `pinch.yaml`, a `docker-compose.yml` or a GitHub workflow is a mapping, and is left out) and takes
the string value of every `image` key (`community.docker.docker_container`, or a module of a collection that nests it)
as a container image.
The `{{ a.b }}` references are resolved against the `vars` of the play the image is in, over the variables of each
inventory (the `group_vars` and `host_vars` in the same directory): one image per distinct result, so two inventories
with different tags give two images. Only plain dotted lookups are resolved; an image with a filter or a loop variable
(`{{ item.image }}`) is left out, and the repository shows a failed `ansible`/`containers` check that lists it.
Symbolic links are not followed.

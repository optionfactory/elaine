# Security

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public
issue. Only the latest release is supported; fixes go into a new release.

## What elaine is, and what it trusts

Elaine shows the state of an organization's GitHub repositories: what their manifests declare, their vulnerable and
outdated dependencies, the container images they run. `sync` and `scan` run on a machine with a GitHub token and the
build tools; `serve` runs on a server, receives the results by push and shows them to the employees behind a Google
login. This document is about `serve`.

**The repositories are trusted.** Their content, `elaine.yaml` included, is written by the organization's own
developers: elaine reports what a manifest declares (stewards, tiers, compliance answers) and does not verify it. What
that trust covers on `serve`: manifest text, names, descriptions, dependency names and scanner output are shown to
every employee and sent in the alert mails, always as text (template text nodes, `textContent` for the logs, escaped
in the mails), so an author can mislead but cannot inject markup.

## What `serve` holds

- **In `data_dir`**: `stats.json`, for every repository of the organization, private ones included: name,
  description, GitHub URL, dates, flags, the whole manifest (stewards, domains, environments, compliance answers,
  sensitivity), paths of configuration files, container images, vulnerable and outdated dependencies; `images.json`,
  the vulnerabilities of each image; `stats/logs/<repo>/<scanner>.log`, the raw output of the build tools on the
  scanning machine. Elaine writes them readable only by its own user (files 0600, directories 0700); `data_dir` itself
  is left to the deployment.
- **In `elaine.conf.json`**: the OAuth client secret, the push token, and the GitHub token if the same file serves for
  scanning. Elaine refuses to start when every user of the machine can read it.
- **In memory**: the key that signs the sessions, new at every start.
- **Not held**: source code, the list of dependencies checked against OSV (kept on the scanning machine), any list of
  users or record of page views. A session is only a signed email and expiry in the browser.

## Who can do what

| Who | Can | Cannot, or only within these bounds |
| --- | --- | --- |
| Anyone on the internet | reach `/favicon.svg`, `/login`, `/oidc/callback`, `/logout` and `PUT /api/snapshot` | read any page or data: everything else needs the login. Make the server read a push body: the token is checked first, and a refused push is logged |
| An employee signed in with an account of `login.domain` | read everything above, for every repository, private ones included, and every scanner log: there are no roles | change anything: the dashboard has no write operation |
| Whoever holds the push token, the scanning machine | replace everything the dashboard shows and every log; decide what the alert mails say and whether they are sent | read back what the server holds; write outside `data_dir` (log names are checked); push more than 16 MB gzipped or 256 MB unzipped; link a repository outside `https://github.com/<organization>/`; mail more than 200 entries at once; sign in |
| A repository author | write any manifest, which elaine shows as declared | inject markup in the pages or the mails |
| The reverse proxy | see in clear the session cookies, the push token and all data; it ends TLS | (it is trusted: `serve` speaks plain HTTP, trusts no forwarded header, and builds the login redirect from `public_url`) |
| Google, as the identity provider | sign in whoever controls an account of the Workspace domain, or the domain itself | sign in an account outside `login.domain`: `domain` is required, and the `hd` claim of the ID token must match it |
| The mail relay, and the mailbox | read the repository names, the dependency and image names with their advisories, and the address of the dashboard | (STARTTLS with a verified certificate is required, except to a relay on loopback; the relay takes the mail without credentials, by the address of the server) |
| Other users of the server | reach the loopback port, where the same login and token apply | read the data or the settings, given the modes above |

The pages load nothing from elsewhere: the two script libraries (`ftl` and `httpc`) are built into the binary, pinned
by their hash. Every page carries a Content-Security-Policy that runs only the site's own scripts and, by their hash,
the inline scripts of that very page; every response says `nosniff` and sends no referrer; the API is never cached;
the pages cannot be framed.

## The login

The authorization code flow with PKCE (S256) and a 128-bit state bound to a short cookie (`__Secure-`, `HttpOnly`,
`SameSite=Lax`, limited to `/oidc` and 10 minutes). The ID token comes straight from Google's token endpoint over TLS,
so its signature is not checked, as OpenID Connect allows; its issuer, audience, expiry, verified email and `hd` claim
are. The session is a cookie (`__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`) holding the email and the expiry,
signed with HMAC-SHA256 and checked before it is read. After the login, the browser goes back only to a path of this
site. Sign-ins and refused logins are logged with the email; no token or secret is ever logged.

## Known limits

- **No roles, no per-repository access**: one login sees everything, private repositories included.
- **Sessions cannot be revoked** before their 12 hours, except by restarting `serve`; signing out clears the cookie in
  that browser only, and `/logout` is a plain link.
- **The push token is a single shared secret** without expiry; rotating it means changing both settings files.
- **No history**: a push replaces everything, and the alerts compare only with the previous push, so the token holder
  can hide a vulnerability from the next alert by pushing once without it. The first push after a loss of data sends
  no mail.
- **No rate limit, no timeouts** inside `serve`: they are the reverse proxy's job, as are TLS and HSTS. The proxy must
  allow bodies of up to 16 MB on `/api/snapshot` only.
- **Without `login`**, the dashboard is open to whoever reaches its port.
- **The scanning machine** runs the build tools of every repository with the GitHub token at hand; its sandbox is
  outside the scope of this document.

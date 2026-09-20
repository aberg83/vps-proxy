# vps-proxy

A native Ubuntu reverse-proxy stack using nginx, GeoIP2, CrowdSec, Tailscale,
UFW, Certbot, Monit, unattended upgrades, and healthchecks.io. Public ports are
limited to HTTP/HTTPS; backend traffic crosses Tailscale.

## Safety model

- Application authentication remains the primary security boundary.
- Tailscale ACLs restrict which backend ports the VPS can reach.
- GeoIP, CrowdSec, and rate limiting reduce opportunistic traffic.
- The setup script validates every input before changing the system.
- Generated nginx changes are rolled back if validation or certificate issuance fails.
- Only sites recorded in the project's managed-state file can be pruned.
- Existing unrelated nginx configurations and UFW rules are not silently deleted.

## Files

```text
setup-vps-proxy.sh
vps-proxy.conf.example
sites.list.example
lib/validation.sh
tests/validation-test.sh
scripts/public-safety-check.sh
.github/workflows/ci.yml
```

The real `vps-proxy.conf` and `sites.list` are intentionally ignored. Keep
them on the VPS; do not commit deployment inventory or credentials.

## Important migration for installations created before this change

Do this **before merging/pulling the change that removes the tracked
`sites.list`**:

```bash
sudo install -d -m 700 -o root -g root /etc/vps-proxy
sudo install -m 600 -o root -g root /opt/vps-proxy/sites.list /etc/vps-proxy/sites.list
sudo grep -vE '^[[:space:]]*(#|$)' /etc/vps-proxy/sites.list
```

Then ensure `vps-proxy.conf` contains:

```bash
SITES_REGISTRY_FILE="/etc/vps-proxy/sites.list"
```

Only after confirming the copied entries should you merge, pull, and rerun the
script.

## Fresh installation

1. Provision Ubuntu 22.04 or 24.04 and initially connect through the provider
   console or temporary public SSH.
2. Clone the repository:

   ```bash
   git clone git@github.com:youruser/vps-proxy.git /opt/vps-proxy
   cd /opt/vps-proxy
   ```

3. Create the private files:

   ```bash
   sudo cp vps-proxy.conf.example vps-proxy.conf
   sudo install -d -m 700 -o root -g root /etc/vps-proxy
   sudo install -m 600 -o root -g root sites.list.example /etc/vps-proxy/sites.list
   sudoedit vps-proxy.conf
   sudoedit /etc/vps-proxy/sites.list
   ```

4. Fill in MaxMind credentials for the first run. They may be removed after
   `GeoLite2-Country.mmdb` has been downloaded.
5. Run:

   ```bash
   bash -n setup-vps-proxy.sh
   sudo ./setup-vps-proxy.sh
   ```

6. If Tailscale was not enrolled automatically, run:

   ```bash
   sudo tailscale up --ssh --advertise-tags=tag:vps
   ```

7. In a separate terminal, prove Tailscale SSH and sudo work before accepting
   the script's firewall/root-lock confirmation.
8. Limit `tag:vps` in the Tailscale policy to only the listed backend ports.
9. Point each public DNS name at the VPS and rerun if certificate issuance
   initially failed.

The first run prints a read-only deploy key for GitHub. Add it under
**Settings → Deploy keys** without write access.

## Site registry

Each non-comment line is:

```text
domain:port
domain:port:streaming
```

Example:

```text
media.example.com:8096:streaming
requests.example.com:5055
```

Entries must use lowercase DNS hostnames, ports 1–65535, and either
`standard` or `streaming`. Duplicate domains and malformed lines abort
before package installation or configuration changes.

Edit the private registry on the VPS, validate, and rerun:

```bash
sudoedit /etc/vps-proxy/sites.list
sudo ./setup-vps-proxy.sh
```

Removing an entry deletes its nginx configuration and certificate only if the
site was previously recorded in `/var/lib/vps-proxy/managed-sites`.
Unrelated nginx files are never pruned.

## Firewall behavior

Every run reconciles the required UFW defaults and rules. If an unrestricted
public port-22/OpenSSH rule is found, the script aborts and asks you to review
and remove it manually. It never guesses which administrator-created rule is
safe to delete.

Root's password can be locked only when `NEW_SUDO_USERNAME` names an existing
sudo user and you interactively confirm working Tailscale SSH and sudo access.

## Health monitoring

When `HEALTHCHECKS_PING_URL` is set, the timer checks:

- nginx, CrowdSec, its firewall bouncer, and Tailscale are active;
- `nginx -t` passes;
- a real HTTPS request succeeds locally using the configured production
  hostname, SNI, certificate validation, path, and expected status.

Configure a lightweight backend path and its accepted statuses:

```bash
HEALTHCHECK_DOMAIN="media.example.com"
HEALTHCHECK_PATH="/health"
HEALTHCHECK_EXPECTED_STATUS="200"
```

If the domain is blank, the first registry entry is used. Defaults accept
200, 301, or 302 at `/` for backward compatibility.

## Routine checks

```bash
sudo monit status
sudo cscli decisions list
sudo ufw status verbose
sudo nginx -t
sudo systemctl list-timers
sudo journalctl -u weekly-full-upgrade --since "-8 days"
```

Automatic security upgrades are enabled. A weekly full upgrade also covers
third-party Tailscale and CrowdSec repositories. Automatic reboot remains
disabled; check `/var/run/reboot-required` and reboot at a convenient time.

## Making the repository public

The current tracked tree contains examples only, and CI rejects common token,
private-key, Healthchecks UUID, and deployment-hostname patterns. That does
not sanitize existing Git history.

Before changing visibility, read [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md). If
past commits contain deployment details or identifying commit metadata you do
not want public, publish the sanitized current tree as a fresh repository or
rewrite the history first.

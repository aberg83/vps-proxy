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
- A catch-all default server closes connections for unknown hostnames and bare-IP
  scans, presenting a self-signed certificate instead of a real site's.

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

## Fresh installation

1. Provision Ubuntu 22.04 or 24.04 and initially connect through the provider
   console or temporary public SSH.
2. Clone the repository as root. Everything in the checkout runs as root, so
   the script refuses to start unless the checkout and its parent
   directories are root-owned and not writable by group or others:

   ```bash
   sudo git clone https://github.com/youruser/vps-proxy.git /opt/vps-proxy
   cd /opt/vps-proxy
   ```

   Update it later with `sudo git -C /opt/vps-proxy pull`.

3. Create the private files:

   ```bash
   sudo cp vps-proxy.conf.example vps-proxy.conf
   sudo install -d -m 700 -o root -g root /etc/vps-proxy
   sudo install -m 600 -o root -g root sites.list.example /etc/vps-proxy/sites.list
   sudoedit vps-proxy.conf
   sudoedit /etc/vps-proxy/sites.list
   ```

4. Fill in MaxMind credentials for the first run. They are stored in
   root-only `/etc/GeoIP.conf` so the database keeps updating automatically.
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

Every run reconciles the required UFW defaults and rules. If any rule opens
SSH to every source address (`22`, `22/tcp`, `ssh`, `OpenSSH`, a port list or
range containing 22, or the same on a non-Tailscale interface), the script
lists those rules and aborts so you can remove them manually. Rules limited to
`tailscale0` or to specific source addresses are left alone. It never guesses
which administrator-created rule is safe to delete.

Root's password can be locked only when `NEW_SUDO_USERNAME` names an existing
sudo user and you interactively confirm working Tailscale SSH and sudo access.

## HTTPS

Every proxied site serves HTTP/2 and sends
`Strict-Transport-Security: max-age=31536000` (without `includeSubDomains`
or `preload`). Set `HSTS_MAX_AGE` in `vps-proxy.conf` to change the lifetime,
or `0` to disable it. Browsers remember the header for that long, so disable
it well before a proxied domain ever needs plain HTTP again.

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
third-party Tailscale and CrowdSec repositories and refreshes CrowdSec's hub
content. Set `UPGRADE_HEALTHCHECKS_PING_URL` to a separate healthchecks.io
check (7-day period, about 1 day of grace) to be alerted when it fails. Automatic reboot remains
disabled; check `/var/run/reboot-required` and reboot at a convenient time.

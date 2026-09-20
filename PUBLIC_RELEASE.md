# Public release checklist

## Current-tree controls

- `vps-proxy.conf`, `sites.list`, `.env`, and `*.local` are ignored.
- The committed registry is an example using `example.com`.
- CI runs syntax checks, ShellCheck, validation tests, and a likely-secret scan.
- Real settings and deployment inventory live outside the repository.

## Historical disclosure found during the September 2026 audit

No credentials were found in the 27 reachable commits: no private keys,
GitHub tokens, Tailscale auth keys, Healthchecks check UUIDs, MaxMind licence
keys, or stored passwords.

The existing history does contain:

- real service hostnames and backend port numbers in older `sites.list`
  versions; and
- the author's email address in Git commit metadata.

Public DNS names and commit-author emails are not authentication secrets, but
they are identifying and infrastructure information. Making this existing
repository public exposes them even though the current files are sanitized.

## Choose one publication method

1. **Accept the historical disclosure.** Change the existing repository to
   public after merging and passing CI.
2. **Cleanest option:** create a new repository from the sanitized current tree
   with no old `.git` history, then make that repository public.
3. Rewrite the existing history with `git filter-repo`, force-push every
   rewritten branch/tag, and have every clone replaced. This is disruptive and
   should be done only with a verified backup.

Also review GitHub Actions logs, releases, issues, pull requests, branch names,
repository description, deploy keys, and collaborator access. Those are not
part of the Git file tree.

## Final checks

- [ ] Existing VPS registry copied to `/etc/vps-proxy/sites.list` before merge
- [ ] CI passes on the public-readiness pull request
- [ ] No real values were added to example files
- [ ] Publication method selected
- [ ] A licence selected if reuse by others is intended
- [ ] GitHub secret scanning and push protection enabled where available

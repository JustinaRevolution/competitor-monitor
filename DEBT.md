# Known Debt

Tracked, not hidden. Each item has a plan. Last reviewed: 2026-08-20 (software-engineering-fundamentals audit).

- [ ] Monolithic commits: entire history is 3 large commits. Rewriting pushed history is not worth it. Going forward: one logical change per commit. (Law 1)
- [ ] Full OWASP Top 10 deep audit not yet run against the app. Basic controls in place: secrets in env, chmod 600 .env, Secure cookies in production, TLS via certbot, startup fail-fast. Next step: dedicated security pass with the security-audit skill. (Law 6)
- [ ] Rollback is manual, not one command. Current path: checkout previous commit locally, scp app files, restart service. Could become `deploy/rollback.sh <commit>` later. (Law 7)
- [ ] Backups are on-server only (daily 02:30, 14-day rotation, restore tested 2026-08-20). Upgrade path: nightly off-site copy (DO snapshot or pull to local machine). (Law 8)
- [ ] No external uptime monitoring. /health endpoint exists and the stripe watchdog checks the site, but no UptimeRobot-style outside probe. Free tier exists; set up when convenient. (Law 5)

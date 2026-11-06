#!/usr/bin/env bash
# One-time preparation of a fresh Ubuntu 24.04 VPS for the MasterDB backend.
#
# Upload the whole deploy/ folder (this script installs deploy/backup/ too) and
# run as root on the server:
#     bash deploy/vps-setup.sh "<ci public key>" [api domain]
# e.g.
#     bash deploy/vps-setup.sh "ssh-ed25519 AAAA... ci" db-api.nordencapital.ca
#
# The domain can also come from the API_DOMAIN environment variable. With a
# domain, Caddy serves the API over HTTPS on it (the A record must already point
# here) and the bare IP answers 404. Without one, the API is plain HTTP on the
# IP until you re-run the script with the domain.
#
# Safe to re-run: every step checks before it changes anything.
#
# What it deliberately does NOT do is turn off password or root login. Doing that
# before a key login has been proven to work is how people lock themselves out of
# a server, so it is a separate, manual step (see the end of this file).

set -euo pipefail

CI_PUBKEY="${1:-}"
API_DOMAIN="${2:-${API_DOMAIN:-}}"   # Empty = plain HTTP on the IP.
APP_DIR=/opt/masterdb       # Must match the target in .github/workflows/ci-cd.yml.
DEPLOY_USER=deploy

[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 1; }

echo "==> System update"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# Keep existing config files if a package ships a new version (no prompt).
apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade -y
apt-get install -y ca-certificates curl gnupg python3 ufw fail2ban unattended-upgrades \
  debian-keyring debian-archive-keyring apt-transport-https

# Security patches install themselves. A box nobody logs into for weeks is
# exactly the one that falls behind.
# Written explicitly: dpkg-reconfigure in noninteractive mode only applies the
# debconf default and does not guarantee the periodic runs are switched on.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades

echo "==> Docker Engine + Compose plugin (official repository, not the distro's)"
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker

# Without rotation, container logs grow until the disk is full and Postgres stops.
if [ ! -f /etc/docker/daemon.json ]; then
  cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF
  systemctl restart docker
fi

echo "==> Caddy (official repository) as the public entrance"
# The backend listens on 127.0.0.1:8080 only (see docker-compose.yml). Caddy is
# the only thing on 80/443 and gets HTTPS certificates automatically once a
# domain points here.
if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  chmod o+r /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi

# Written when the file is not ours yet (no marker line), or when a domain is
# given and the file does not serve it yet (plain-IP mode -> HTTPS). Otherwise
# left alone, so hand edits survive a re-run. The old file is always kept.
CADDY_WRITE=no
grep -q '^# MasterDB' /etc/caddy/Caddyfile 2>/dev/null || CADDY_WRITE=yes
if [ -n "$API_DOMAIN" ] && ! grep -qF "$API_DOMAIN {" /etc/caddy/Caddyfile 2>/dev/null; then
  CADDY_WRITE=yes
fi
if [ "$CADDY_WRITE" = yes ]; then
  [ -f /etc/caddy/Caddyfile ] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%Y%m%d%H%M%S)"
  if [ -n "$API_DOMAIN" ]; then
    # HTTPS on the domain. Caddy fetches and renews the Let's Encrypt
    # certificate itself and redirects http:// to https://. The backend sets no
    # security headers of its own, so HSTS is added here (no preload: that is
    # hard to undo). The bare IP gets a 404, not a redirect, so IP scanners are
    # not pointed at the API.
    cat > /etc/caddy/Caddyfile <<EOF
# MasterDB - reverse proxy to the backend container on 127.0.0.1:8080.
# Keep this first line: vps-setup.sh uses it as a marker and will not overwrite
# this file on a re-run.

# The API, HTTPS only.
${API_DOMAIN} {
	encode zstd gzip
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy 127.0.0.1:8080
}

# Anything else on port 80 (the bare IP, unknown Host headers): no API here.
:80 {
	respond "Not found" 404
}
EOF
  else
    cat > /etc/caddy/Caddyfile <<'EOF'
# MasterDB - reverse proxy to the backend container on 127.0.0.1:8080.
# Keep this first line: vps-setup.sh uses it as a marker and will not overwrite
# this file on a re-run.

# No domain yet: plain HTTP on the server's IP.
# Once an A record points here, re-run: bash vps-setup.sh "<ci key>" <api domain>
:80 {
	reverse_proxy 127.0.0.1:8080
}
EOF
  fi
fi
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl enable caddy
systemctl reload-or-restart caddy

echo "==> Deploy user for CI"
# CI logs in as this user, not root. It is in the docker group, which is
# root-equivalent in practice, but it keeps CI off the root account and lets the
# key be revoked without touching how you log in yourself.
id "$DEPLOY_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$DEPLOY_USER"
usermod -aG docker "$DEPLOY_USER"
install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" /home/$DEPLOY_USER/.ssh
touch /home/$DEPLOY_USER/.ssh/authorized_keys
if [ -n "$CI_PUBKEY" ] && ! grep -qxF "$CI_PUBKEY" /home/$DEPLOY_USER/.ssh/authorized_keys; then
  echo "$CI_PUBKEY" >> /home/$DEPLOY_USER/.ssh/authorized_keys
fi
chown "$DEPLOY_USER:$DEPLOY_USER" /home/$DEPLOY_USER/.ssh/authorized_keys
chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys

install -d -m 750 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$APP_DIR"

echo "==> Swap"
# A safety net for the moment a deploy briefly runs the old and new backend
# side by side next to Postgres. Not meant to be used in normal operation.
if ! swapon --show | grep -q .; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Prefer RAM: Postgres' buffers and the JVM heap should not be pushed to disk
# just because the page cache wants room.
echo 'vm.swappiness=10' > /etc/sysctl.d/99-masterdb.conf
sysctl -p /etc/sysctl.d/99-masterdb.conf

echo "==> Nightly database backup + weekly restore test"
# The scripts and units live next to this file in deploy/backup/ (one copy, the
# one in git, instead of a second copy pasted in here that could drift). Upload
# the whole deploy/ folder, not just this script. Nothing runs yet on a fresh
# server: the timers just fail harmlessly until the first deploy has started
# the masterdb-postgres container.
BACKUP_SRC="$(cd "$(dirname "$0")" && pwd)/backup"
for f in masterdb-backup.sh masterdb-restore-test.sh masterdb-backup-status.py masterdb-backup.service masterdb-backup.timer \
         masterdb-restore-test.service masterdb-restore-test.timer; do
  [ -f "$BACKUP_SRC/$f" ] || { echo "Missing $BACKUP_SRC/$f: upload the whole deploy/ folder."; exit 1; }
done
install -m 0755 -o root -g root "$BACKUP_SRC/masterdb-backup.sh" /usr/local/sbin/masterdb-backup
install -m 0755 -o root -g root "$BACKUP_SRC/masterdb-restore-test.sh" /usr/local/sbin/masterdb-restore-test
# Writes /var/backups/masterdb/status.json after every run (needs python3, part of Ubuntu).
install -m 0755 -o root -g root "$BACKUP_SRC/masterdb-backup-status.py" /usr/local/sbin/masterdb-backup-status
for u in masterdb-backup.service masterdb-backup.timer masterdb-restore-test.service masterdb-restore-test.timer; do
  install -m 0644 -o root -g root "$BACKUP_SRC/$u" "/etc/systemd/system/$u"
done
install -d -m 700 -o root -g root /var/backups/masterdb
systemctl daemon-reload
systemctl enable --now masterdb-backup.timer masterdb-restore-test.timer

echo "==> Firewall"
# NOTE: Docker writes its own iptables rules, so a port published in
# docker-compose.yml ("8080:8080") is reachable even though ufw does not list it.
# ufw protects the host; docker-compose.yml decides what the containers expose.
# Plain port rules, not app profiles ("OpenSSH", "Nginx Full"), so the rules
# do not depend on which packages happen to be installed.
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "==> fail2ban (SSH brute-force protection)"
systemctl enable --now fail2ban

echo
echo "Done."
docker --version
docker compose version
caddy version
echo
echo "Next, by hand, ONLY after confirming key login works in a second terminal:"
echo "  put these lines in /etc/ssh/sshd_config.d/00-masterdb.conf (00- is read before"
echo "  cloud-init's 50-cloud-init.conf, and the first value read wins):"
echo "    PasswordAuthentication no"
echo "    KbdInteractiveAuthentication no"
echo "    PermitRootLogin prohibit-password"
echo "  then: sshd -t && sshd -T | grep -Ei 'passwordauth|kbdinteractive|permitroot' && systemctl reload ssh"

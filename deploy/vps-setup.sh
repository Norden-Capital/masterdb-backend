#!/usr/bin/env bash
# One-time preparation of a fresh Ubuntu 24.04 VPS for the MasterDB backend.
#
# Run as root on the server:
#     bash vps-setup.sh "<ci public key>"
#
# Safe to re-run: every step checks before it changes anything.
#
# What it deliberately does NOT do is turn off password or root login. Doing that
# before a key login has been proven to work is how people lock themselves out of
# a server, so it is a separate, manual step (see the end of this file).

set -euo pipefail

CI_PUBKEY="${1:-}"
APP_DIR=/opt/masterdb       # Must match the target in .github/workflows/ci-cd.yml.
DEPLOY_USER=deploy

[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 1; }

echo "==> System update"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# Keep existing config files if a package ships a new version (no prompt).
apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade -y
apt-get install -y ca-certificates curl gnupg ufw fail2ban unattended-upgrades \
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

# Written once. The marker keeps a re-run from overwriting the file after the
# domain block below has been switched on by hand; the stock file is kept.
if ! grep -q '^# MasterDB' /etc/caddy/Caddyfile 2>/dev/null; then
  [ -f /etc/caddy/Caddyfile ] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.orig.$(date +%Y%m%d%H%M%S)"
  cat > /etc/caddy/Caddyfile <<'EOF'
# MasterDB - reverse proxy to the backend container on 127.0.0.1:8080.

# Placeholder until DNS exists: plain HTTP on the server's IP.
# Remove this block once the domain block below is enabled.
:80 {
	reverse_proxy 127.0.0.1:8080
}

# Enable when masterdb-api.nordencapital.ca points at this server (A record).
# Caddy then fetches and renews the HTTPS certificate on its own.
# Apply with: systemctl reload caddy
#
# masterdb-api.nordencapital.ca {
# 	encode gzip
# 	reverse_proxy 127.0.0.1:8080
# }
EOF
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

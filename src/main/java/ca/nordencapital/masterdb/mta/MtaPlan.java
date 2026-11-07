package ca.nordencapital.masterdb.mta;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The MTA install, ported from the old app's MtaPlans.mtaScript (Postfix,
 * Dovecot IMAP, OpenDKIM with selector "mail", Roundcube as an option), split
 * into steps that each run as their own root script and are safe to repeat:
 * packages already installed stay, settings are set (not appended), the DKIM
 * key is made only if it does not exist yet. Two changes from the old app:
 * the DKIM key is generated ON the server (opendkim-genkey) instead of in the
 * app, and only its public key is read back; Ubuntu installs never prompt.
 *
 * <p>Every value put into a script is checked first: host and domain names
 * by the server/domain rules, the mailbox login by {@link #LOGIN}, and the
 * mailbox password is single-quoted (and scrubbed from the log).
 */
public final class MtaPlan {

    public static final String SELECTOR = "mail";
    public static final Pattern LOGIN = Pattern.compile("[a-z][a-z0-9_.-]{0,31}");
    static final Pattern NAME = Pattern.compile("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?");
    static final String MARKER = "# masterdb-step: ";

    public record Step(String key, String label, String script, Duration timeout) {
        /** Done by the backend, not on the server. */
        public boolean local() {
            return script == null;
        }
    }

    /** What to install: the server's linked domain and HELO host; webmail is optional. */
    public record Input(String domain, String heloHost, boolean webmail, String webmailLogin, String webmailPassword) {
    }

    private MtaPlan() {
    }

    public static List<Step> steps(Input in) {
        String d = checked(in.domain());
        String h = checked(in.heloHost());
        String keys = "/etc/opendkim/keys/" + d;
        List<Step> out = new ArrayList<>();
        out.add(new Step("preflight", "Check the operating system", script("preflight", """
                . /etc/os-release
                echo "Operating system: $PRETTY_NAME"
                case "$ID:$VERSION_ID" in
                  ubuntu:22.04|ubuntu:24.04|almalinux:8*|almalinux:9*|almalinux:10*) echo "Supported." ;;
                  *) echo "Unsupported: the MTA install supports Ubuntu 22.04/24.04 and AlmaLinux 8/9/10."; exit 3 ;;
                esac
                """), Duration.ofMinutes(1)));
        out.add(new Step("packages", "Install Postfix, Dovecot and OpenDKIM", script("packages", """
                . /etc/os-release
                if [ "$ID" = ubuntu ]; then
                  export DEBIAN_FRONTEND=noninteractive
                  echo "postfix postfix/mailname string %1$s" | debconf-set-selections
                  echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
                  apt-get -o DPkg::Lock::Timeout=300 update -q
                  apt-get -o DPkg::Lock::Timeout=300 install -y -q postfix dovecot-imapd opendkim opendkim-tools
                else
                  dnf install -y -q epel-release dnf-plugins-core
                  case "$VERSION_ID" in 8*) dnf config-manager --set-enabled powertools ;; *) dnf config-manager --set-enabled crb ;; esac
                  dnf install -y -q postfix dovecot opendkim opendkim-tools
                fi
                echo "Packages ready."
                """.formatted(d)), Duration.ofMinutes(20)));
        out.add(new Step("hostname", "Set the host name to " + h, script("hostname", """
                hostnamectl set-hostname '%1$s'
                echo "Host name: $(hostname)"
                """.formatted(h)), Duration.ofMinutes(1)));
        out.add(new Step("postfix", "Configure Postfix", script("postfix", """
                postconf -e 'myhostname = %2$s'
                postconf -e 'mydomain = %1$s'
                postconf -e 'myorigin = $mydomain'
                postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain'
                postconf -e 'inet_interfaces = all'
                postconf -e 'mynetworks = 127.0.0.0/8, [::1]/128'
                postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'
                postconf -e 'home_mailbox = Maildir/'
                echo "Postfix configured for %1$s."
                """.formatted(d, h)), Duration.ofMinutes(2)));
        out.add(new Step("dkim-key", "Make the DKIM key on the server", script("dkim-key", """
                install -d -m 0750 -o opendkim -g opendkim '%1$s'
                if [ -s '%1$s/%2$s.private' ]; then
                  echo "DKIM key already there: kept."
                else
                  opendkim-genkey -b 2048 -d '%3$s' -D '%1$s' -s %2$s
                  echo "DKIM key made (2048-bit RSA, selector %2$s)."
                fi
                chown opendkim:opendkim '%1$s/%2$s.private' '%1$s/%2$s.txt'
                chmod 0600 '%1$s/%2$s.private'
                """.formatted(keys, SELECTOR, d)), Duration.ofMinutes(2)));
        out.add(new Step("opendkim", "Configure OpenDKIM signing", script("opendkim", """
                cat > /etc/opendkim.conf <<'MASTERDB_DKIM_CONFIG'
                Syslog yes
                UMask 007
                Mode sv
                Canonicalization relaxed/simple
                Socket inet:8891@localhost
                UserID opendkim:opendkim
                KeyTable /etc/opendkim/KeyTable
                SigningTable refile:/etc/opendkim/SigningTable
                InternalHosts /etc/opendkim/TrustedHosts
                MASTERDB_DKIM_CONFIG
                printf '%%s\\n' '%2$s._domainkey.%1$s %1$s:%2$s:%3$s/%2$s.private' > /etc/opendkim/KeyTable
                printf '%%s\\n' '*@%1$s %2$s._domainkey.%1$s' > /etc/opendkim/SigningTable
                printf '%%s\\n' '127.0.0.1' '::1' 'localhost' '%1$s' > /etc/opendkim/TrustedHosts
                postconf -e 'smtpd_milters = inet:localhost:8891'
                postconf -e 'non_smtpd_milters = inet:localhost:8891'
                postconf -e 'milter_default_action = tempfail'
                echo "OpenDKIM signs mail from %1$s."
                """.formatted(d, SELECTOR, keys)), Duration.ofMinutes(2)));
        out.add(new Step("services", "Start the services", script("services", """
                systemctl enable opendkim postfix dovecot
                systemctl restart opendkim postfix dovecot
                postfix check
                systemctl is-active postfix opendkim dovecot
                echo "MTA services active."
                """), Duration.ofMinutes(3)));
        if (in.webmail()) {
            String login = in.webmailLogin();
            if (login == null || !LOGIN.matcher(login).matches() || List.of("root", "postfix", "opendkim", "dovecot")
                    .contains(login)) {
                throw new IllegalArgumentException("webmail login");
            }
            out.add(new Step("webmail", "Install Roundcube webmail and the mailbox", script("webmail", """
                    . /etc/os-release
                    if [ "$ID" = ubuntu ]; then
                      export DEBIAN_FRONTEND=noninteractive
                      echo "roundcube-core roundcube/dbconfig-install boolean true" | debconf-set-selections
                      echo "roundcube-core roundcube/database-type select sqlite3" | debconf-set-selections
                      apt-get -o DPkg::Lock::Timeout=300 install -y -q apache2 libapache2-mod-php roundcube roundcube-sqlite3 certbot python3-certbot-apache
                      a2enconf roundcube || true
                      systemctl restart apache2
                    else
                      dnf install -y -q httpd php php-fpm roundcubemail certbot python3-certbot-apache
                      systemctl enable --now httpd php-fpm
                    fi
                    id '%1$s' >/dev/null 2>&1 || useradd -m '%1$s'
                    printf '%%s\\n' %2$s | chpasswd
                    install -d -m 0700 -o '%1$s' -g '%1$s' '/home/%1$s/Maildir'
                    systemctl enable --now dovecot
                    echo "Roundcube installed; mailbox %1$s ready. Point webmail.%3$s at this server and add HTTPS before use."
                    """.formatted(login, shellQuote(login + ":" + in.webmailPassword()), d)), Duration.ofMinutes(20)));
        }
        out.add(new Step("dkim-read", "Read back the DKIM public key", script("dkim-read", """
                cat '%1$s/%2$s.txt'
                """.formatted(keys, SELECTOR)), Duration.ofMinutes(1)));
        out.add(new Step("dns", "Hand the DKIM key to the domain's DNS settings", null, Duration.ofSeconds(30)));
        return out;
    }

    private static String script(String key, String body) {
        return "#!/usr/bin/env bash\n" + MARKER + key + "\nset -euo pipefail\n" + body;
    }

    private static String checked(String name) {
        if (name == null || name.length() > 253 || !NAME.matcher(name).matches() || name.contains("..")) {
            throw new IllegalArgumentException("not a host name");
        }
        return name;
    }

    static String shellQuote(String v) {
        return "'" + v.replace("'", "'\\''") + "'";
    }

    private static final Pattern QUOTED = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern P = Pattern.compile("(?:^|;)\\s*p=([A-Za-z0-9+/=\\s]+)");

    /**
     * The public key from opendkim-genkey's mail.txt
     * ({@code mail._domainkey IN TXT ( "v=DKIM1; h=sha256; k=rsa; " "p=MIIB..." "...IDAQAB" )}),
     * or null if it isn't there.
     */
    public static String dkimPublicKey(String txt) {
        if (txt == null) {
            return null;
        }
        StringBuilder joined = new StringBuilder();
        Matcher q = QUOTED.matcher(txt);
        while (q.find()) {
            joined.append(q.group(1));
        }
        String record = joined.isEmpty() ? txt : joined.toString();
        Matcher p = P.matcher(record);
        if (!p.find()) {
            return null;
        }
        String key = p.group(1).replaceAll("\\s", "");
        return key.length() >= 64 && key.matches("[A-Za-z0-9+/]+={0,2}") ? key : null;
    }
}

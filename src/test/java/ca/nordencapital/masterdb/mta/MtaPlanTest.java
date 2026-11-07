package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.mta.MtaPlan.Input;
import ca.nordencapital.masterdb.mta.MtaPlan.Step;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The MTA plan (ported from the old app's mtaScript) and the log scrubber. */
class MtaPlanTest {

    static final String KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0";

    @Test
    void theStepsPortTheOldScriptAndAreSafeToRepeat() {
        List<Step> steps = MtaPlan.steps(new Input("example.com", "mail.example.com", false, null, null));
        assertThat(steps).extracting(Step::key).containsExactly("preflight", "packages", "hostname", "postfix",
                "dkim-key", "opendkim", "services", "dkim-read", "dns");
        String all = String.join("\n", steps.stream().filter(s -> !s.local()).map(Step::script).toList());
        assertThat(all).contains("postfix dovecot-imapd opendkim opendkim-tools", "hostnamectl set-hostname "
                        + "'mail.example.com'", "postconf -e 'myhostname = mail.example.com'",
                "postconf -e 'mydomain = example.com'", "Socket inet:8891@localhost",
                "printf '%s\\n' 'mail._domainkey.example.com example.com:mail:/etc/opendkim/keys/example.com/mail.private'",
                "printf '%s\\n' '*@example.com mail._domainkey.example.com' > /etc/opendkim/SigningTable",
                "postconf -e 'milter_default_action = tempfail'", "systemctl restart opendkim postfix dovecot",
                "DPkg::Lock::Timeout=300", "debconf-set-selections")
                // The key is made ON the server, once; the app never sends one.
                .contains("if [ -s '/etc/opendkim/keys/example.com/mail.private' ]", "opendkim-genkey -b 2048")
                .doesNotContain("PRIVATE KEY", ">>");
        assertThat(steps).allMatch(s -> s.local() || s.script().startsWith("#!/usr/bin/env bash\n# masterdb-step: "
                + s.key() + "\nset -euo pipefail\n"));
        assertThat(steps.getLast().local()).isTrue();
    }

    @Test
    void webmailIsAnOptionWithTheMailboxPasswordQuoted() {
        List<Step> steps = MtaPlan.steps(new Input("example.com", "mail.example.com", true, "anna", "it's \"secret\" $1"));
        assertThat(steps).extracting(Step::key).contains("webmail").hasSize(10);
        String webmail = steps.stream().filter(s -> s.key().equals("webmail")).findFirst().orElseThrow().script();
        assertThat(webmail).contains("roundcube", "useradd -m 'anna'",
                "printf '%s\\n' 'anna:it'\\''s \"secret\" $1' | chpasswd");
    }

    @Test
    void namesThatCouldBreakTheScriptAreRefused() {
        assertThatThrownBy(() -> MtaPlan.steps(new Input("ex'ample.com", "mail.example.com", false, null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MtaPlan.steps(new Input("example.com", "mail.example.com;reboot", false, null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MtaPlan.steps(new Input("example.com", "mail.example.com", true, "a b", "x")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MtaPlan.steps(new Input("example.com", "mail.example.com", true, "root", "x")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theDkimPublicKeyIsReadFromOpendkimsTxtFile() {
        String txt = "mail._domainkey\tIN\tTXT\t( \"v=DKIM1; h=sha256; k=rsa; \"\n\t  \"p=" + KEY.substring(0, 60)
                + "\"\n\t  \"" + KEY.substring(60) + "\" )  ; ----- DKIM key mail for example.com\n";
        assertThat(MtaPlan.dkimPublicKey(txt)).isEqualTo(KEY);
        assertThat(MtaPlan.dkimPublicKey("v=DKIM1; k=rsa; p=" + KEY)).isEqualTo(KEY);
        assertThat(MtaPlan.dkimPublicKey("cat: /etc/opendkim/keys/x/mail.txt: No such file")).isNull();
        assertThat(MtaPlan.dkimPublicKey("\"p=short\"")).isNull();
    }

    @Test
    void theLogIsScrubbed() {
        LogScrubber s = new LogScrubber(List.of("Mailbox-Secret-42", "abc"));
        assertThat(s.line("chpasswd: anna:Mailbox-Secret-42 set")).isEqualTo("chpasswd: anna:[hidden] set");
        // Too short to be a real secret: left alone (would hide ordinary words).
        assertThat(s.line("abc def")).isEqualTo("abc def");
        assertThat(s.line("DB_PASSWORD=hunter2 token: \"x y z\" api_key=K1")).isEqualTo(
                "DB_PASSWORD=[hidden] token: [hidden] api_key=[hidden]");
        assertThat(s.line("note -----BEGIN OPENSSH PRIVATE KEY-----")).isEqualTo("note [private key hidden]");
        assertThat(s.line("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW")).isNull();
        assertThat(s.line("-----END OPENSSH PRIVATE KEY-----")).isNull();
        assertThat(s.line("after the key")).isEqualTo("after the key");
        assertThat(s.line("-----BEGIN RSA PRIVATE KEY----- MIIE -----END RSA PRIVATE KEY-----"))
                .isEqualTo("[private key hidden]");
        assertThat(s.line("still shown")).isEqualTo("still shown");
    }
}

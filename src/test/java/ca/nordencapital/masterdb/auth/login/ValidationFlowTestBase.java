package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.dns.health.DnsLookup.Mx;
import ca.nordencapital.masterdb.validation.engine.SmtpProber;
import ca.nordencapital.testsupport.FakeDnsLookup;
import ca.nordencapital.testsupport.FakeSmtpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validation tests: a connected fake SSH server linked to probe.example
 * (HELO mail.probe.example, MAIL FROM postmaster@probe.example), and a fake
 * mail server on 127.0.0.1 that checks reach through the SSH server's
 * direct-tcpip, as a real check leaves a VPS. Mail domains used:
 * <ul>
 *   <li>{@code gmail.test}: MX gmail-smtp-in.l.google.com → the fake mail server (paced as Google);</li>
 *   <li>{@code other.test}: MX mx.other.test → the fake mail server.</li>
 * </ul>
 * No test reaches a real mail server, DNS or VPS.
 */
abstract class ValidationFlowTestBase extends ServerFlowTestBase {

    static final FakeSmtpServer SMTP = FakeSmtpServer.SHARED;

    @Autowired
    FakeDnsLookup dns;
    @Autowired
    SmtpProber prober;

    String server;

    @BeforeEach
    void setUpValidation() throws Exception {
        cleanValidation();
        SMTP.reset();
        dns.clear();
        prober.forget();
        String domain = addManual("probe.example");
        server = connectedServer("probe1");
        HttpResponse<String> linked = client.send("PUT", "/api/v1/servers/" + server, owner, "{\"name\":\"probe1\","
                + "\"ip\":\"127.0.0.1\",\"sshPort\":" + SSH.port() + ",\"expiresOn\":\"2027-03-01\",\"domainId\":\""
                + domain + "\"}");
        assertThat(linked.statusCode()).as(linked.body()).isEqualTo(200);
        dns.mx("gmail.test", new Mx(5, "gmail-smtp-in.l.google.com"), new Mx(10, "alt1.gmail-smtp-in.l.google.com"))
                .a("gmail-smtp-in.l.google.com", "127.0.0.1").a("alt1.gmail-smtp-in.l.google.com", "127.0.0.1");
        dns.mx("other.test", new Mx(10, "mx.other.test")).a("mx.other.test", "127.0.0.1");
    }

    @AfterEach
    void tearDownValidation() {
        cleanValidation();
    }

    void cleanValidation() {
        jdbc.update("update validation_jobs set status = 'STOPPED'");
        jdbc.update("delete from validation_jobs");
        jdbc.update("delete from validation_checks");
        jdbc.update("delete from validation_cooldowns");
    }
}

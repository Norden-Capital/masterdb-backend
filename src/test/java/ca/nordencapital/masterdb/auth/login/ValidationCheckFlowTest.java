package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.dns.health.DnsLookup.Mx;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;

/** Validation job 1: single email check through a server, its history and the pacing. */
class ValidationCheckFlowTest extends ValidationFlowTestBase {

    HttpResponse<String> check(String email) throws Exception {
        return post("/api/v1/validation/checks", "{\"email\":\"" + email + "\",\"serverId\":\"" + server + "\"}");
    }

    @Test
    void aValidAddressGoesThroughTheServerWithItsIdentity() throws Exception {
        SMTP.recipient("jane@other.test", "250 2.1.5 Ok");
        HttpResponse<String> res = check("jane@other.test");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"category\":\"VALID\"", "\"smtpCode\":250", "\"mxHost\":\"mx.other.test\"",
                "\"heloHost\":\"mail.probe.example\"", "\"mailFrom\":\"postmaster@probe.example\"",
                "\"serverName\":\"probe1\"", "refused two made-up ones");
        assertThat(SMTP.commands()).contains("EHLO mail.probe.example", "MAIL FROM:<postmaster@probe.example>",
                "RCPT TO:<jane@other.test>").doesNotContain("DATA");
        // Two made-up controls at the same domain, each after RSET.
        assertThat(SMTP.commands().stream().filter(c -> c.startsWith("RCPT TO:<") && c.endsWith("@other.test>")))
                .hasSize(3);
        assertThat(get("/api/v1/validation/checks").body()).contains("\"email\":\"jane@other.test\"",
                "\"totalItems\":1", "\"checkedBy\":\"owner@example.com\"");
    }

    @Test
    void theSixCategories() throws Exception {
        SMTP.recipient("gone@other.test", "550 5.1.1 <gone@other.test>: Recipient address rejected: User unknown");
        assertThat(check("gone@other.test").body()).contains("\"category\":\"BOUNCE\"", "doesn't exist");

        SMTP.recipient("full@other.test", "452 4.2.2 Mailbox full");
        assertThat(check("full@other.test").body()).contains("\"category\":\"SOFT_BOUNCE\"");

        SMTP.recipient("pol@other.test", "550 5.7.1 Message rejected due to local policy");
        assertThat(check("pol@other.test").body()).contains("\"category\":\"REJECT\"");

        SMTP.recipient("any@other.test", "250 Ok").others("250 Ok");
        assertThat(check("any@other.test").body()).contains("\"category\":\"CATCH_ALL\"");

        dns.mx("dead.test", new Mx(0, ""));
        assertThat(check("x@dead.test").body()).contains("\"category\":\"BOUNCE\"", "null MX");
        assertThat(SMTP.connections()).isEqualTo(4);

        dns.fail("slow.test");
        assertThat(check("x@slow.test").body()).contains("\"category\":\"UNKNOWN\"", "couldn't be looked up");
    }

    @Test
    void gmailDisabledAndTheFirstClearAnswerIsFinal() throws Exception {
        SMTP.recipient("old@gmail.test", "550-5.2.1 The email account that you tried to reach is disabled.\n"
                + "550 5.2.1 https://support.google.com/mail/?p=DisabledUser x1si");
        String body = check("old@gmail.test").body();
        assertThat(body).contains("\"category\":\"BOUNCE\"", "\"mxHost\":\"gmail-smtp-in.l.google.com\"");
        // One mail server asked, not the next ones.
        assertThat(SMTP.connections()).isEqualTo(1);
    }

    @Test
    void anUnreachableMailServerMovesOnToTheNext() throws Exception {
        dns.mx("two.test", new Mx(5, "down.two.test"), new Mx(10, "up.two.test"))
                .a("down.two.test", "127.0.0.2").a("up.two.test", "127.0.0.1");
        SMTP.recipient("a@two.test", "550 5.1.1 User unknown");
        String body = check("a@two.test").body();
        assertThat(body).contains("\"category\":\"BOUNCE\"", "\"mxHost\":\"up.two.test\"", "no connection");
    }

    @Test
    void rateLimitIsUnknownAndPausesTheProviderForThisServerInTheDatabase() throws Exception {
        SMTP.recipient("a@gmail.test", "421 4.7.28 Our system has detected an unusual rate of unsolicited mail. "
                + "Try again later.");
        assertThat(check("a@gmail.test").body()).contains("\"category\":\"UNKNOWN\"", "slow down");
        Timestamp until = jdbc.queryForObject("select cooldown_until from validation_cooldowns where provider = "
                + "'GOOGLE'", Timestamp.class);
        assertThat(until.toInstant()).isEqualTo(T0.plusSeconds(120));

        int before = SMTP.connections();
        SMTP.recipient("b@gmail.test", "250 Ok");
        assertThat(check("b@gmail.test").body()).contains("\"category\":\"UNKNOWN\"", "is paused for this server "
                + "until 09:02 UTC");
        assertThat(SMTP.connections()).isEqualTo(before);
        // Another provider is not paused.
        SMTP.recipient("c@other.test", "250 Ok");
        assertThat(check("c@other.test").body()).contains("\"category\":\"VALID\"");

        clock.set(T0.plusSeconds(121));
        assertThat(check("b@gmail.test").body()).contains("\"category\":\"VALID\"");
    }

    @Test
    void microsoftNoMailboxCodeOnTheTargetIsABounce() throws Exception {
        dns.mx("contoso.test", new Mx(0, "contoso-test.mail.protection.outlook.com"))
                .a("contoso-test.mail.protection.outlook.com", "127.0.0.1");
        SMTP.recipient("gone@contoso.test", "550 5.5.0 Requested action not taken: mailbox unavailable "
                + "(S2017062302) [x.prod.protection.outlook.com]");
        assertThat(check("gone@contoso.test").body()).contains("\"category\":\"BOUNCE\"");
    }

    @Test
    void aSilentMailServerTimesOutAsUnknown() throws Exception {
        SMTP.greeting("STALL");
        String body = check("x@other.test").body();
        assertThat(body).contains("\"category\":\"UNKNOWN\"", "broke off or timed out");
    }

    @Test
    void refusedSenderIsNeverABounce() throws Exception {
        SMTP.mailFrom("550 5.1.1 sender rejected");
        assertThat(check("x@other.test").body()).contains("\"category\":\"UNKNOWN\"", "sender address");
    }

    @Test
    void wrongInputAndServersThatCantValidate() throws Exception {
        assertThat(check("not-an-email").statusCode()).isEqualTo(400);
        assertThat(post("/api/v1/validation/checks", "{\"email\":\"a@other.test\"}").statusCode()).isEqualTo(400);

        String bare = id(post("/api/v1/servers", "{\"name\":\"bare\",\"ip\":\"127.0.0.1\",\"sshPort\":2222,"
                + "\"expiresOn\":\"2027-03-01\"}").body());
        HttpResponse<String> res = post("/api/v1/validation/checks", "{\"email\":\"a@other.test\",\"serverId\":\""
                + bare + "\"}");
        assertThat(res.statusCode()).isEqualTo(409);
        assertThat(res.body()).contains("SERVER_NOT_READY", "not connected");
        assertThat(get("/api/v1/validation/servers").body()).contains("\"name\":\"probe1\"", "\"ready\":true",
                "\"name\":\"bare\"", "\"ready\":false");
        assertThat(SMTP.connections()).isZero();
    }

    @Test
    void permissions() throws Exception {
        String viewer = member("VALIDATION:VIEW");
        assertThat(client.send("POST", "/api/v1/validation/checks", viewer, "{\"email\":\"a@other.test\","
                + "\"serverId\":\"" + server + "\"}").statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/validation/checks", viewer, null).statusCode()).isEqualTo(200);
        String nobody = member("DNS:VIEW");
        assertThat(client.send("GET", "/api/v1/validation/servers", nobody, null).statusCode()).isEqualTo(403);
    }
}

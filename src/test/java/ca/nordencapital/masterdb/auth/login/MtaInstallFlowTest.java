package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.mta.MtaInstallService;
import ca.nordencapital.testsupport.FakeSshServer.Reply;
import ca.nordencapital.testsupport.NamecheapStub;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Server management job 4: the MTA install as a background job against the
 * fake SSH server: live progress, scrubbed log, DKIM made on the server and
 * handed to the DNS preview flow, restart recovery, permissions.
 */
class MtaInstallFlowTest extends ServerFlowTestBase {

    static final String MAILBOX_PASSWORD = "Mailbox-Pass-2026!";

    @Autowired
    MtaInstallService installs;

    final AtomicReference<String> zone = new AtomicReference<>();
    final CountDownLatch release = new CountDownLatch(1);
    String domain;
    String server;
    String dkim;

    @BeforeEach
    void serverWithDomain() throws Exception {
        zone.set(NamecheapStub.fixture("getHosts-ok"));
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        NamecheapStub.answer("namecheap.domains.dns.getHosts", p -> zone.get());
        NamecheapStub.answer("namecheap.domains.dns.setHosts", p -> {
            zone.set(DnsRecordFlowTest.render(p));
            return NamecheapStub.fixture("setHosts-ok");
        });
        assertThat(post("/api/v1/dns/domains/import", "{\"names\":[\"example-one.com\"]}").statusCode()).isEqualTo(200);
        domain = id(get("/api/v1/dns/domains?q=example-one").body());
        server = connectedServer("mx1");
        HttpResponse<String> linked = client.send("PUT", "/api/v1/servers/" + server, owner, "{\"name\":\"mx1\","
                + "\"ip\":\"127.0.0.1\",\"sshPort\":" + SSH.port() + ",\"expiresOn\":\"2027-03-01\",\"domainId\":\""
                + domain + "\"}");
        assertThat(linked.statusCode()).as(linked.body()).isEqualTo(200);

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        dkim = Base64.getEncoder().encodeToString(rsa.generateKeyPair().getPublic().getEncoded());
        SSH.on("masterdb-step: preflight", 0, "Operating system: Ubuntu 24.04.1 LTS\nSupported.\n");
        // apt prints a lot; one line carries a password-looking value, and something prints a private key.
        SSH.on("masterdb-step: packages", 0, "Reading package lists...\nSetting up postfix (3.8.6-1build2) ...\n"
                + "debconf: smtp_sasl_password=hunter2-from-apt\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                + "-----END OPENSSH PRIVATE KEY-----\nPackages ready.\n");
        SSH.on("masterdb-step: dkim-key", 0, "DKIM key made (2048-bit RSA, selector mail).\n");
        SSH.on("masterdb-step: services", 0, "active\nactive\nactive\nMTA services active.\n");
        SSH.on("masterdb-step: dkim-read", 0, "mail._domainkey\tIN\tTXT\t( \"v=DKIM1; h=sha256; k=rsa; \"\n\t  \"p="
                + dkim.substring(0, 200) + "\"\n\t  \"" + dkim.substring(200) + "\" )  ; ----- DKIM key mail for "
                + "example-one.com\n");
        SSH.on("masterdb-step: webmail", 0, "Setting up roundcube ...\nchpasswd: anna:" + MAILBOX_PASSWORD
                + " ok\nRoundcube installed; mailbox anna ready.\n");
    }

    @AfterEach
    void releaseGates() {
        release.countDown();
    }

    HttpResponse<String> start(String token, String body) throws Exception {
        return client.send("POST", "/api/v1/mta/installs", token, body);
    }

    String installNow(String extra) throws Exception {
        HttpResponse<String> res = start(owner, "{\"serverId\":\"" + server + "\"" + extra + "}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(202);
        assertThat(res.body()).contains("\"status\":\"QUEUED\"");
        return id(res.body());
    }

    String finished(String job) throws Exception {
        String path = "/api/v1/mta/installs/" + job;
        await(() -> {
            String b = body(path);
            return !b.contains("\"status\":\"QUEUED\"") && !b.contains("\"status\":\"RUNNING\"");
        });
        return get(path).body();
    }

    String body(String path) {
        try {
            return get(path).body();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static void await(Supplier<Boolean> condition) throws InterruptedException {
        long end = System.currentTimeMillis() + 30_000;
        while (!condition.get()) {
            assertThat(System.currentTimeMillis()).as("waited 30 s").isLessThan(end);
            Thread.sleep(50);
        }
    }

    static String publicId(String body) {
        return id(body);
    }

    @Test
    void theInstallRunsInTheBackgroundAndHandsDkimToTheDnsPreview() throws Exception {
        assertThat(get("/api/v1/mta/candidates").body()).contains("\"name\":\"mx1\"", "\"ready\":true",
                "\"domain\":\"example-one.com\"", "\"heloHost\":\"mail.example-one.com\"");
        String job = installNow("");
        String done = finished(job);
        assertThat(done).contains("\"status\":\"SUCCEEDED\"", "\"stepsDone\":9", "\"stepsTotal\":9",
                "\"dkimSelector\":\"mail\"", "\"dkimPublicKey\":\"" + dkim + "\"", "\"domain\":\"example-one.com\"",
                "{\"key\":\"dns\",\"label\":\"Hand the DKIM key to the domain's DNS settings\",\"state\":\"DONE\"}");
        String log = jdbc.queryForObject("select log from mta_installs", String.class);
        assertThat(log).contains("▶ Step 1 of 9: Check the operating system", "Setting up postfix",
                "smtp_sasl_password=[hidden]", "[private key hidden]", "▶ Step 9 of 9", "✓ MTA installed.")
                .doesNotContain("hunter2", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "END OPENSSH");

        // Each step ran on the server as its own root script; the key was made there; no private key was sent.
        assertThat(SSH.exchanges()).filteredOn(e -> e.has("masterdb-step: ")).hasSize(8)
                .allMatch(e -> e.command().equals("bash -s"));
        assertThat(SSH.exchanges()).anyMatch(e -> e.stdin().contains("opendkim-genkey -b 2048 -d 'example-one.com'"));
        assertThat(SSH.exchanges()).noneMatch(e -> e.stdin().contains("PRIVATE KEY"));

        // The public key is now the domain's DKIM setting, and nothing was written at Namecheap.
        assertThat(get("/api/v1/dns/domains/" + domain + "/dns-settings").body()).contains("\"dkimSelector\":\"mail\"",
                "\"dkimPublicKey\":\"" + dkim + "\"", "\"mailIp\":\"127.0.0.1\"");
        assertThat(NamecheapStub.requests("namecheap.domains.dns.setHosts")).isEmpty();

        // Writing DNS is the DNS module's flow: preview (before/after + token) → confirm → snapshot → write.
        HttpResponse<String> preview = get("/api/v1/dns/domains/" + domain + "/records/preview");
        assertThat(preview.statusCode()).as(preview.body()).isEqualTo(200);
        assertThat(preview.body()).contains("{\"change\":\"ADD\",\"managed\":true,\"record\":{\"name\":\"mail._domainkey\","
                + "\"type\":\"TXT\",\"address\":\"v=DKIM1; k=rsa; p=" + dkim + "\"", "\"address\":\"127.0.0.1\"");
        String token = DnsFlowTestBase.id(preview.body().replace("\"token\":\"", "\"publicId\":\""));
        HttpResponse<String> written = post("/api/v1/dns/domains/" + domain + "/records/apply",
                "{\"token\":\"" + token + "\"}");
        assertThat(written.statusCode()).as(written.body()).isEqualTo(200);
        assertThat(written.body()).contains("\"verified\":true");
        assertThat(NamecheapStub.requests("namecheap.domains.dns.setHosts")).hasSize(1);
        assertThat(jdbc.queryForObject("select count(*) from dns_snapshots", Integer.class)).isEqualTo(1);

        assertThat(jdbc.queryForList("select action from activity_log where action like 'MTA_%' or action = "
                + "'DNS_SETTINGS_CHANGED' order by id", String.class)).containsExactly("MTA_INSTALL_STARTED",
                "DNS_SETTINGS_CHANGED", "MTA_INSTALL_FINISHED");
        assertThat(jdbc.queryForObject("select mta_domain from servers", String.class)).isEqualTo("example-one.com");
        assertThat(get("/api/v1/mta/installs?serverId=" + server).body()).contains("\"status\":\"SUCCEEDED\"");
    }

    @Test
    void progressIsLiveAndOneInstallRunsAtATime() throws Exception {
        CountDownLatch gate = new CountDownLatch(1);
        SSH.on("masterdb-step: services", new Reply(0, "MTA services active.\n", gate));
        String job = installNow("");
        String path = "/api/v1/mta/installs/" + job;
        await(() -> body(path).contains("\"currentStep\":\"services\""));
        String mid = get(path).body();
        assertThat(mid).contains("\"status\":\"RUNNING\"", "\"stepsDone\":6", "\"stepsTotal\":9",
                "{\"key\":\"opendkim\",\"label\":\"Configure OpenDKIM signing\",\"state\":\"DONE\"}",
                "{\"key\":\"services\",\"label\":\"Start the services\",\"state\":\"RUNNING\"}",
                "{\"key\":\"dkim-read\",\"label\":\"Read back the DKIM public key\",\"state\":\"PENDING\"}");
        int length = Integer.parseInt(mid.replaceAll(".*\"logLength\":(\\d+).*", "$1"));
        assertThat(get(path + "?logFrom=" + length).body()).contains("\"log\":\"\"", "\"logFrom\":" + length);

        HttpResponse<String> second = start(owner, "{\"serverId\":\"" + server + "\"}");
        assertThat(second.statusCode()).isEqualTo(409);
        assertThat(second.body()).contains("\"code\":\"MTA_INSTALL_RUNNING\"");
        assertThat(client.send("DELETE", "/api/v1/servers/" + server, owner, null).statusCode()).isEqualTo(409);

        gate.countDown();
        assertThat(finished(job)).contains("\"status\":\"SUCCEEDED\"");
    }

    @Test
    void aRestartMarksTheJobInterruptedAndItCanBeRunAgain() throws Exception {
        // The backend died mid-install: the row is still RUNNING and nothing works on it.
        jdbc.update("insert into mta_installs (server_id, domain_id, domain_name, helo_host, status, steps_total, "
                + "steps_done, current_step, log, created_at, started_at, updated_at) select id, domain_id, "
                + "'example-one.com', 'mail.example-one.com', 'RUNNING', 9, 3, 'postfix', 'partial\n', now(), now(), "
                + "now() from servers");
        assertThat(start(owner, "{\"serverId\":\"" + server + "\"}").statusCode()).isEqualTo(409);

        assertThat(installs.recoverInterrupted()).isEqualTo(1);
        String old = jdbc.queryForObject("select public_id::text from mta_installs", String.class);
        assertThat(get("/api/v1/mta/installs/" + old).body()).contains("\"status\":\"INTERRUPTED\"",
                "\"stepsDone\":3", "The backend restarted during the install. Run it again",
                "{\"key\":\"postfix\",\"label\":\"Configure Postfix\",\"state\":\"FAILED\"}");

        assertThat(finished(installNow(""))).contains("\"status\":\"SUCCEEDED\"", "\"stepsDone\":9");
    }

    @Test
    void aFailedStepStopsTheJobWithTheReasonAndARerunFinishesIt() throws Exception {
        SSH.on("masterdb-step: dkim-key", 1, "opendkim-genkey: command not found\n");
        String failed = finished(installNow(""));
        assertThat(failed).contains("\"status\":\"FAILED\"", "\"stepsDone\":4",
                "Step \\\"Make the DKIM key on the server\\\" failed (exit code 1)",
                "{\"key\":\"dkim-key\",\"label\":\"Make the DKIM key on the server\",\"state\":\"FAILED\"}",
                "opendkim-genkey: command not found");
        assertThat(jdbc.queryForObject("select mta_installed_at from servers", Object.class)).isNull();

        SSH.on("masterdb-step: dkim-key", 0, "DKIM key already there: kept.\n");
        assertThat(finished(installNow(""))).contains("\"status\":\"SUCCEEDED\"");
        // Running it again on a server that has an MTA is an edit.
        String creator = member("MTA:CREATE");
        assertThat(start(creator, "{\"serverId\":\"" + server + "\"}").statusCode()).isEqualTo(403);
    }

    @Test
    void theWebmailPasswordIsUsedOnceAndNeverStoredOrLogged() throws Exception {
        HttpResponse<String> bad = start(owner, "{\"serverId\":\"" + server + "\",\"webmail\":true,"
                + "\"webmailLogin\":\"root\",\"webmailPassword\":\"short\"}");
        assertThat(bad.statusCode()).isEqualTo(400);
        assertThat(bad.body()).contains("\"field\":\"webmailLogin\"", "\"field\":\"webmailPassword\"")
                .doesNotContain("short\"");

        String done = finished(installNow(",\"webmail\":true,\"webmailLogin\":\"anna\",\"webmailPassword\":\""
                + MAILBOX_PASSWORD + "\""));
        assertThat(done).contains("\"status\":\"SUCCEEDED\"", "\"stepsTotal\":10", "\"webmailLogin\":\"anna\"",
                "chpasswd: anna:[hidden] ok").doesNotContain(MAILBOX_PASSWORD);
        // It went to the server once, inside the script on stdin (never on a command line).
        assertThat(SSH.exchanges()).filteredOn(e -> e.stdin().contains(MAILBOX_PASSWORD)).hasSize(1)
                .allMatch(e -> e.has("masterdb-step: webmail") && !e.command().contains(MAILBOX_PASSWORD));
        String everything = String.join("|", jdbc.queryForList("select row_to_json(m)::text from mta_installs m",
                String.class)) + String.join("|", jdbc.queryForList("select details::text from activity_log",
                String.class));
        assertThat(everything).doesNotContain(MAILBOX_PASSWORD);
    }

    @Test
    void notReadyServersAreRefusedWithTheReason() throws Exception {
        String bare = addServerAt("bare", 1);
        assertThat(get("/api/v1/mta/candidates").body()).contains("\"name\":\"bare\"", "\"ready\":false",
                "Connect to this server first");
        HttpResponse<String> res = start(owner, "{\"serverId\":\"" + bare + "\"}");
        assertThat(res.statusCode()).isEqualTo(409);
        assertThat(res.body()).contains("\"code\":\"SERVER_NOT_READY\"", "Connect to this server first");
    }

    @Test
    void permissionsAreChecked() throws Exception {
        String none = member("SERVERS:VIEW");
        assertThat(client.send("GET", "/api/v1/mta/candidates", none, null).statusCode()).isEqualTo(403);
        assertThat(start(none, "{\"serverId\":\"" + server + "\"}").statusCode()).isEqualTo(403);
        String viewer = member("MTA:VIEW");
        assertThat(client.send("GET", "/api/v1/mta/candidates", viewer, null).statusCode()).isEqualTo(200);
        assertThat(start(viewer, "{\"serverId\":\"" + server + "\"}").statusCode()).isEqualTo(403);
        assertThat(jdbc.queryForObject("select count(*) from mta_installs", Integer.class)).isZero();
    }

    String addServerAt(String name, int port) throws Exception {
        HttpResponse<String> res = post("/api/v1/servers", "{\"name\":\"" + name + "\",\"ip\":\"127.0.0.1\","
                + "\"sshPort\":" + port + ",\"expiresOn\":\"2027-03-01\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(201);
        return id(res.body());
    }
}

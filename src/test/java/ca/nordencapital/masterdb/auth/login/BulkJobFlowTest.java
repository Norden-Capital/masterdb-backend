package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.validation.bulk.BulkRunner;
import ca.nordencapital.testsupport.FakeSshServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Validation job 2: bulk jobs in the background, through the fake SSH server(s) and the fake mail server. */
class BulkJobFlowTest extends ValidationFlowTestBase {

    static final FakeSshServer SSH2 = new FakeSshServer(0);

    @Autowired
    BulkRunner runner;

    @AfterEach
    void stopJobs() {
        jdbc.update("update validation_jobs set status = 'STOPPED'");
        jdbc.update("delete from validation_jobs");
    }

    String start(String emails, String... servers) throws Exception {
        String ids = String.join(",", java.util.Arrays.stream(servers).map(s -> "\"" + s + "\"").toList());
        HttpResponse<String> res = post("/api/v1/validation/jobs", "{\"name\":\"Test list\",\"emails\":\""
                + emails.replace("\"", "\\\"").replace("\n", "\\n") + "\",\"serverIds\":[" + ids + "]}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(201);
        return id(res.body());
    }

    String job(String id) throws Exception {
        return get("/api/v1/validation/jobs/" + id).body();
    }

    /** Polls the job until its body contains {@code text} (10 s at most). */
    String waitFor(String id, String text) throws Exception {
        Instant end = Instant.now().plus(Duration.ofSeconds(10));
        String body = job(id);
        while (!body.contains(text) && Instant.now().isBefore(end)) {
            Thread.sleep(50);
            body = job(id);
        }
        assertThat(body).contains(text);
        return body;
    }

    @Test
    void aPastedListIsCheckedInTheBackgroundAndTheTotalsAddUp() throws Exception {
        SMTP.recipient("a@other.test", "250 Ok").recipient("b@other.test", "550 5.1.1 User unknown")
                .recipient("c@other.test", "552 5.2.2 Mailbox full").recipient("d@other.test", "554 5.7.1 Policy")
                .recipient("e@other.test", "451 4.3.0 Temporary failure");
        String id = start("a@other.test\nB@Other.test\nb@other.test\nnot an email\n\n\"c@other.test\",Jane\n"
                + "d@other.test\ne@other.test", server);
        String body = waitFor(id, "\"status\":\"COMPLETED\"");
        assertThat(body).contains("\"total\":5", "\"pending\":0", "\"checked\":5", "\"valid\":1", "\"bounce\":1",
                "\"softBounce\":1", "\"reject\":1", "\"catchAll\":0", "\"unknown\":1", "\"duplicates\":1",
                "\"invalid\":1", "\"name\":\"probe1\",\"ip\":\"127.0.0.1\",\"checked\":5");
        assertThat(jdbc.queryForObject("select count(*) from validation_job_emails where category is null",
                Integer.class)).isZero();
        assertThat(jdbc.queryForList("select action from activity_log where action like 'VALIDATION_JOB%' order by "
                + "id", String.class)).containsExactly("VALIDATION_JOB_STARTED", "VALIDATION_JOB_FINISHED");
        assertThat(get("/api/v1/validation/jobs").body()).contains("\"totalItems\":1", "\"name\":\"Test list\"");
    }

    @Test
    void stopKeepsTheResultsAndResumeGoesOnWithTheRest() throws Exception {
        SMTP.delay(300).others("250 Ok");
        String id = start("a@other.test\nb@other.test\nc@other.test\nd@other.test\ne@other.test\nf@other.test",
                server);
        waitFor(id, "\"checked\":1,");
        HttpResponse<String> stopped = post("/api/v1/validation/jobs/" + id + "/stop", null);
        assertThat(stopped.statusCode()).as(stopped.body()).isEqualTo(200);
        assertThat(stopped.body()).contains("\"status\":\"STOPPED\"", "Stopped by owner@example.com");
        Thread.sleep(800);
        int checked = jdbc.queryForObject("select total - pending from validation_jobs", Integer.class);
        Thread.sleep(500);
        assertThat(jdbc.queryForObject("select total - pending from validation_jobs", Integer.class))
                .as("nothing is checked after Stop").isEqualTo(checked).isLessThan(6);
        assertThat(post("/api/v1/validation/jobs/" + id + "/stop", null).statusCode()).isEqualTo(409);
        assertThat(client.send("DELETE", "/api/v1/validation/jobs/" + id, owner, null).statusCode()).isEqualTo(204);

        String again = start("a@other.test\nb@other.test\nc@other.test", server);
        post("/api/v1/validation/jobs/" + again + "/stop", null);
        SMTP.delay(0);
        Thread.sleep(500);
        HttpResponse<String> resumed = post("/api/v1/validation/jobs/" + again + "/resume", null);
        assertThat(resumed.statusCode()).as(resumed.body()).isEqualTo(200);
        assertThat(waitFor(again, "\"status\":\"COMPLETED\"")).contains("\"total\":3", "\"pending\":0");
    }

    @Test
    void retryUnknownStaysInTheSameJobAndCountsOnce() throws Exception {
        SMTP.recipient("a@other.test", "451 4.3.0 Temporary failure").recipient("b@other.test", "250 Ok");
        String id = start("a@other.test\nb@other.test", server);
        waitFor(id, "\"status\":\"COMPLETED\"");
        assertThat(job(id)).contains("\"unknown\":1", "\"valid\":1");

        SMTP.recipient("a@other.test", "250 Ok");
        HttpResponse<String> retry = post("/api/v1/validation/jobs/" + id + "/retry-unknown", null);
        assertThat(retry.statusCode()).as(retry.body()).isEqualTo(200);
        String body = waitFor(id, "\"status\":\"COMPLETED\"");
        assertThat(body).contains("\"total\":2", "\"valid\":2", "\"unknown\":0", "\"retries\":1");
        assertThat(post("/api/v1/validation/jobs/" + id + "/retry-unknown", null).statusCode()).isEqualTo(409);
        assertThat(get("/api/v1/validation/jobs").body()).contains("\"totalItems\":1");
    }

    @Test
    void aSlowDownAnswerPausesTheProviderAndTheAddressIsCheckedAfterThePause() throws Exception {
        SMTP.recipient("a@gmail.test", "421 4.7.28 Unusual rate. Try again later.").recipient("b@other.test", "250 Ok");
        String id = start("a@gmail.test\nb@other.test", server);
        String body = waitFor(id, "Paused for Gmail / Google Workspace");
        assertThat(body).contains("\"status\":\"RUNNING\"", "\"pending\":1", "\"valid\":1", "\"state\":\"WAITING\"");
        assertThat(jdbc.queryForObject("select attempts from validation_job_emails where email = 'a@gmail.test'",
                Integer.class)).isEqualTo(1);
        assertThat(get("/api/v1/validation/pacing").body()).contains("\"label\":\"Gmail / Google Workspace\"",
                "\"serverName\":\"probe1\"", "4.7.28");

        SMTP.recipient("a@gmail.test", "250 Ok");
        clock.set(T0.plusSeconds(121));
        assertThat(waitFor(id, "\"status\":\"COMPLETED\"")).contains("\"valid\":2", "\"unknown\":0");
    }

    @Test
    void theWorkRotatesBetweenServers() throws Exception {
        SSH2.reset();
        SSH2.authorize(publicKey);
        SSH2.on("MASTERDB_LOGIN_TEST", 0, "MASTERDB_LOGIN_TEST\nID=ubuntu\nVERSION_ID=\"24.04\"\nMASTERDB_UID=0\n");
        String domain2 = addManual("probe2.example");
        HttpResponse<String> added = post("/api/v1/servers", "{\"name\":\"probe2\",\"ip\":\"127.0.0.1\",\"sshPort\":"
                + SSH2.port() + ",\"expiresOn\":\"2027-03-01\",\"domainId\":\"" + domain2 + "\"}");
        String second = id(added.body());
        post("/api/v1/servers/" + second + "/connect", null);
        assertThat(post("/api/v1/servers/" + second + "/host-key/trust", "{\"fingerprint\":\"" + SSH2.fingerprint()
                + "\"}").body()).contains("CONNECTED");

        SMTP.delay(60).others("250 Ok");
        StringBuilder emails = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            emails.append("u").append(i).append("@other.test\n");
        }
        String id = start(emails.toString(), server, second);
        waitFor(id, "\"status\":\"COMPLETED\"");
        Map<String, Object> perServer = jdbc.queryForMap("select count(*) filter (where server_name = 'probe1') as "
                + "a, count(*) filter (where server_name = 'probe2') as b from validation_job_emails");
        assertThat(((Number) perServer.get("a")).intValue()).isPositive();
        assertThat(((Number) perServer.get("b")).intValue()).isPositive();
        assertThat(SMTP.commands()).contains("EHLO mail.probe.example", "EHLO mail.probe2.example");
    }

    @Test
    void aRestartResumesRunningJobs() throws Exception {
        SMTP.recipient("a@other.test", "250 Ok").recipient("b@other.test", "550 5.1.1 User unknown");
        // As left by a backend that died mid-job: RUNNING, one address done, one claimed by a worker that is gone.
        String id = jdbc.queryForObject("insert into validation_jobs (name, status, total, pending, valid, "
                + "created_at, started_at, updated_at) values ('Before restart', 'RUNNING', 2, 1, 1, now(), now(), "
                + "now()) returning public_id", String.class);
        long jobId = jdbc.queryForObject("select id from validation_jobs", Long.class);
        jdbc.update("insert into validation_job_servers (job_id, server_id) select ?, id from servers where name = "
                + "'probe1'", jobId);
        jdbc.update("insert into validation_job_emails (job_id, seq, email, category, checked_at) values (?, 1, "
                + "'a@other.test', 'VALID', now())", jobId);
        jdbc.update("insert into validation_job_emails (job_id, seq, email, claimed_by) values (?, 2, "
                + "'b@other.test', 12345)", jobId);
        runner.resumeAfterRestart();
        assertThat(waitFor(id, "\"status\":\"COMPLETED\"")).contains("\"valid\":1", "\"bounce\":1", "\"pending\":0");
        assertThat(SMTP.commands()).contains("RCPT TO:<b@other.test>").doesNotContain("RCPT TO:<a@other.test>");
    }

    @Test
    void refusalsAndPermissions() throws Exception {
        assertThat(post("/api/v1/validation/jobs", "{\"emails\":\"nothing here\",\"serverIds\":[\"" + server
                + "\"]}").statusCode()).isEqualTo(400);
        assertThat(post("/api/v1/validation/jobs", "{\"emails\":\"a@other.test\",\"serverIds\":[]}").statusCode())
                .isEqualTo(400);
        String bare = id(post("/api/v1/servers", "{\"name\":\"bare\",\"ip\":\"127.0.0.1\",\"sshPort\":2222,"
                + "\"expiresOn\":\"2027-03-01\"}").body());
        HttpResponse<String> notReady = post("/api/v1/validation/jobs", "{\"emails\":\"a@other.test\",\"serverIds\":"
                + "[\"" + bare + "\"]}");
        assertThat(notReady.statusCode()).isEqualTo(409);
        assertThat(notReady.body()).contains("SERVER_NOT_READY");

        SMTP.delay(2000);
        String id = start("a@other.test", server);
        assertThat(client.send("DELETE", "/api/v1/validation/jobs/" + id, owner, null).statusCode()).isEqualTo(409);

        String viewer = member("VALIDATION:VIEW");
        assertThat(client.send("POST", "/api/v1/validation/jobs/" + id + "/stop", viewer, null).statusCode())
                .isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/validation/jobs/" + id, viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("PUT", "/api/v1/validation/pacing/GOOGLE", viewer, "{\"gapMs\":1,\"globalGapMs\":1,"
                + "\"rateCooldownS\":1,\"blockCooldownS\":1,\"maxCooldownS\":1}").statusCode()).isEqualTo(403);
        post("/api/v1/validation/jobs/" + id + "/stop", null);
    }
}

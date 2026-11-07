package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** Validation job 3: a job's addresses, its exports, and List status across jobs. */
class ValidationResultsFlowTest extends ValidationFlowTestBase {

    String run(String name, String emails) throws Exception {
        HttpResponse<String> res = post("/api/v1/validation/jobs", "{\"name\":\"" + name + "\",\"emails\":\""
                + emails.replace("\n", "\\n") + "\",\"serverIds\":[\"" + server + "\"]}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(201);
        String id = id(res.body());
        Instant end = Instant.now().plus(Duration.ofSeconds(10));
        while (!get("/api/v1/validation/jobs/" + id).body().contains("\"status\":\"COMPLETED\"")
                && Instant.now().isBefore(end)) {
            Thread.sleep(50);
        }
        return id;
    }

    @Test
    void addressesExportsAndListStatus() throws Exception {
        SMTP.recipient("a@other.test", "250 Ok").recipient("b@other.test", "550 5.1.1 User unknown")
                .recipient("c@other.test", "451 4.3.0 Temporary failure")
                .recipient("=d@other.test", "550 5.7.1 \"blocked\" by policy");
        String id = run("March leads / Canada", "a@other.test\nb@other.test\nc@other.test\n=d@other.test");

        String bounces = get("/api/v1/validation/jobs/" + id + "/emails?category=BOUNCE").body();
        assertThat(bounces).contains("\"totalItems\":1", "\"email\":\"b@other.test\"", "doesn't exist");
        assertThat(get("/api/v1/validation/jobs/" + id + "/emails?category=PENDING").body())
                .contains("\"totalItems\":0");
        assertThat(get("/api/v1/validation/jobs/" + id + "/emails?q=a@").body()).contains("\"totalItems\":1");

        HttpResponse<String> valid = get("/api/v1/validation/jobs/" + id + "/export?category=VALID");
        assertThat(valid.statusCode()).isEqualTo(200);
        assertThat(valid.body()).isEqualTo("a@other.test\r\n");
        assertThat(valid.headers().firstValue("content-disposition").orElse(""))
                .contains("march-leads-canada-valid.txt");

        HttpResponse<String> details = get("/api/v1/validation/jobs/" + id + "/export?category=DETAILS");
        assertThat(details.headers().firstValue("content-type").orElse("")).startsWith("text/csv");
        assertThat(details.body()).contains("email,category,smtp_code,mail_server,server,checked_at,reason,"
                + "provider_reply", "\"b@other.test\",\"BOUNCE\",\"550\",\"mx.other.test\",\"probe1\"",
                "\"'=d@other.test\",\"REJECT\"", "\"\"blocked\"\"");
        assertThat(details.body().lines().count()).isEqualTo(5);
        assertThat(get("/api/v1/validation/jobs/" + id + "/export?category=nope").statusCode()).isEqualTo(400);
        assertThat(jdbc.queryForList("select details->>'category' from activity_log where action = "
                + "'VALIDATION_EXPORTED' order by id", String.class)).containsExactly("VALID", "DETAILS");

        // A second job: c@ is now valid. List status counts each address once, by its latest result.
        SMTP.recipient("c@other.test", "250 Ok").recipient("e@other.test", "250 Ok");
        run("Second", "C@other.test\ne@other.test");
        String status = get("/api/v1/validation/status").body();
        assertThat(status).contains("\"addresses\":5", "\"jobs\":2", "\"VALID\":3", "\"BOUNCE\":1",
                "\"REJECT\":1", "\"UNKNOWN\":0");
        String latestValid = get("/api/v1/validation/status/emails?category=VALID").body();
        assertThat(latestValid).contains("\"totalItems\":3", "\"jobName\":\"Second\"");
    }

    @Test
    void exportNeedsTheExportPermission() throws Exception {
        String id = run("x", "a@other.test");
        String viewer = member("VALIDATION:VIEW");
        assertThat(client.send("GET", "/api/v1/validation/jobs/" + id + "/export?category=VALID", viewer, null)
                .statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/validation/status", viewer, null).statusCode()).isEqualTo(200);
    }
}

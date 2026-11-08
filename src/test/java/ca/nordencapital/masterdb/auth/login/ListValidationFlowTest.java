package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * List management, job 4: bulk validation of a list or one part, through the
 * fake SSH server and fake mail server. The addresses come from the list in
 * the database (no 50,000 limit), the totals add up, the list shows its
 * latest results, and the exports keep the list's own columns.
 */
class ListValidationFlowTest extends ValidationFlowTestBase {

    @BeforeEach
    void setUpListValidation() {
        ListFlowTestBase.cleanLists(jdbc);
    }

    @AfterEach
    void tearDownListValidation() {
        ListFlowTestBase.cleanLists(jdbc);
    }

    String seed(int split, List<String> columns, List<List<String>> rows, String... emails) {
        return ListFlowTestBase.seed(jdbc, Timestamp.from(clock.instant()), "Leads", "", "", split, columns, rows,
                emails);
    }

    HttpResponse<String> startOn(String list, Integer part) throws Exception {
        return post("/api/v1/validation/jobs", "{\"listId\":\"" + list + "\"" + (part == null ? "" : ",\"part\":"
                + part) + ",\"serverIds\":[\"" + server + "\"]}");
    }

    String waitFor(String path, String text) throws Exception {
        Instant end = Instant.now().plus(Duration.ofSeconds(10));
        String body = get(path).body();
        while (!body.contains(text) && Instant.now().isBefore(end)) {
            Thread.sleep(50);
            body = get(path).body();
        }
        assertThat(body).contains(text);
        return body;
    }

    @Test
    void aPartIsValidatedFromTheDatabaseAndTheListShowsItsResults() throws Exception {
        SMTP.recipient("a@other.test", "250 Ok").recipient("b@other.test", "550 5.1.1 User unknown")
                .recipient("c@other.test", "552 5.2.2 Mailbox full").recipient("d@other.test", "250 Ok")
                .recipient("e@other.test", "451 4.3.0 Try later");
        String list = seed(3, List.of("Name", "Email", "City"), List.of(
                List.of("Ann", "a@other.test", "Montreal"), List.of("Bob", "b@other.test", "Laval"),
                List.of("Ann again", "A@other.test", "Montreal"), List.of("Cy", "c@other.test", "Quebec"),
                List.of("Dee", "d@other.test", "=Levis"), List.of("Eve", "e@other.test", "Gatineau")),
                "a@other.test", "b@other.test", "A@other.test", "c@other.test", "d@other.test", "e@other.test");

        HttpResponse<String> started = startOn(list, 1);
        assertThat(started.statusCode()).as(started.body()).isEqualTo(201);
        String job = id(started.body());
        assertThat(started.body()).contains("\"source\":\"LIST\"", "\"name\":\"Leads · part 1\"",
                "\"status\":\"PREPARING\"", "\"list\":{\"publicId\":\"" + list + "\",\"name\":\"Leads\",\"part\":1}");
        // Part 1 = a, b, A (A is a repeat of a: checked once, counted as a duplicate).
        String done = waitFor("/api/v1/validation/jobs/" + job, "\"status\":\"COMPLETED\"");
        assertThat(done).contains("\"total\":2", "\"pending\":0", "\"valid\":1", "\"bounce\":1",
                "\"duplicates\":1");

        HttpResponse<String> whole = startOn(list, null);
        String job2 = id(whole.body());
        assertThat(whole.body()).contains("\"name\":\"Leads\"");
        String done2 = waitFor("/api/v1/validation/jobs/" + job2, "\"status\":\"COMPLETED\"");
        assertThat(done2).contains("\"total\":5", "\"duplicates\":1", "\"valid\":2", "\"bounce\":1", "\"softBounce\":1", "\"unknown\":1",
                "\"pending\":0");
        int sum = jdbc.queryForObject("select valid + bounce + soft_bounce + reject + catch_all + unknown + pending "
                + "from validation_jobs where public_id = ?::uuid", Integer.class, job2);
        assertThat(sum).isEqualTo(5);

        // The list's latest results: newest answer per address over both jobs.
        String detail = waitFor("/api/v1/lists/" + list, "\"UNKNOWN\":1");
        assertThat(detail).contains("\"VALID\":2", "\"BOUNCE\":1", "\"SOFT_BOUNCE\":1", "\"UNKNOWN\":1");

        // Exports keep the list's own columns next to the result.
        String csv = get("/api/v1/validation/jobs/" + job2 + "/export?category=DETAILS").body();
        assertThat(csv).startsWith("﻿\"Name\",\"Email\",\"City\",category,smtp_code,mail_server,server,"
                + "checked_at,reason,provider_reply\r\n\"Ann\",\"a@other.test\",\"Montreal\",\"VALID\",\"250\"");
        assertThat(csv).contains("\"Dee\",\"d@other.test\",\"'=Levis\",\"VALID\"");
        String valid = get("/api/v1/validation/jobs/" + job2 + "/export?category=VALID&format=csv").body();
        assertThat(valid.split("\r\n")).hasSize(3);
        assertThat(get("/api/v1/validation/jobs/" + job2 + "/export?category=VALID").body())
                .isEqualTo("a@other.test\r\nd@other.test\r\n");
        // Paging through the job's addresses reads them by number.
        assertThat(get("/api/v1/validation/jobs/" + job2 + "/emails?size=2&page=2").body())
                .contains("\"totalItems\":5", "\"email\":\"e@other.test\"").doesNotContain("d@other.test");
    }

    @Test
    void aBigListHasNoFiftyThousandLimitAndCantBeDeletedWhileItRuns() throws Exception {
        SMTP.delay(200).others("250 Ok");
        String list = seed(0, null, null, "first@other.test");
        long id = jdbc.queryForObject("select id from lists where public_id = ?::uuid", Long.class, list);
        jdbc.update("insert into contacts (email, domain) select 'u' || g || '@other.test', 'other.test' from "
                + "generate_series(2, 60000) g");
        jdbc.update("insert into list_members (list_id, seq, part_no, contact_id, email) select ?, "
                + "row_number() over (order by c.id) + 1, 1, c.id, c.email from contacts c where c.email like 'u%'", id);
        jdbc.update("update lists set records = 60000 where id = ?", id);
        jdbc.update("update list_parts set records = 60000, last_seq = 60000 where list_id = ?", id);

        HttpResponse<String> started = startOn(list, null);
        assertThat(started.statusCode()).as(started.body()).isEqualTo(201);
        String job = id(started.body());
        assertThat(waitFor("/api/v1/validation/jobs/" + job, "\"status\":\"RUNNING\"")).contains("\"total\":60000");
        assertThat(get("/api/v1/lists/" + list).body()).contains("\"running\":{\"publicId\":\"" + job + "\"");
        HttpResponse<String> blocked = client.send("DELETE", "/api/v1/lists/" + list, owner, null);
        assertThat(blocked.statusCode()).isEqualTo(409);
        assertThat(blocked.body()).contains("A validation job is running on this list");

        assertThat(post("/api/v1/validation/jobs/" + job + "/stop", null).statusCode()).isEqualTo(200);
        Thread.sleep(500);
        assertThat(client.send("DELETE", "/api/v1/lists/" + list, owner, null).statusCode()).isEqualTo(204);
        // The job and its results stay; it just no longer points at a list.
        assertThat(get("/api/v1/validation/jobs/" + job).body()).contains("\"source\":\"LIST\"", "\"list\":{}");
    }

    @Test
    void validatingAListNeedsBothRunPermissions() throws Exception {
        String list = seed(0, null, null, "a@other.test");
        String body = "{\"listId\":\"" + list + "\",\"serverIds\":[\"" + server + "\"]}";
        String validationOnly = member("VALIDATION:RUN");
        HttpResponse<String> refused = client.send("POST", "/api/v1/validation/jobs", validationOnly, body);
        assertThat(refused.statusCode()).isEqualTo(403);
        assertThat(refused.body()).contains("Lists run permission");
        String listsOnly = member("LISTS:RUN");
        assertThat(client.send("POST", "/api/v1/validation/jobs", listsOnly, body).statusCode()).isEqualTo(403);
        String both = member("VALIDATION:RUN", "LISTS:RUN");
        assertThat(client.send("POST", "/api/v1/validation/jobs", both, body).statusCode()).isEqualTo(201);

        assertThat(post("/api/v1/validation/jobs", "{\"listId\":\"" + list + "\",\"part\":4,\"serverIds\":[\""
                + server + "\"]}").statusCode()).isEqualTo(400);
        assertThat(post("/api/v1/validation/jobs", "{\"listId\":\"" + list + "\",\"emails\":\"x@other.test\","
                + "\"serverIds\":[\"" + server + "\"]}").statusCode()).isEqualTo(400);
        jdbc.update("update lists set status = 'IMPORTING'");
        assertThat(startOn(list, null).statusCode()).isEqualTo(409);
    }
}

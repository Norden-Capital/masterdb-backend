package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.lists.imports.ListFiles;
import ca.nordencapital.masterdb.lists.imports.ListImporter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** List management, job 2: chunked upload, column mapping, the background import and its report. */
class ListUploadFlowTest extends ListFlowTestBase {

    @Autowired
    ListImporter importer;
    @Autowired
    ListFiles files;

    @Test
    void chunksResumeAndARepeatedChunkChangesNothing() throws Exception {
        StringBuilder text = new StringBuilder("email\n");
        for (int i = 1; i <= 7000; i++) {
            text.append("user").append(i).append("@example.invalid\n");
        }
        byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
        assertThat(bytes.length).isGreaterThan(2 * CHUNK);
        String id = id(create("Resumed", "resumed.txt", bytes.length, "").body());
        assertThat(get("/api/v1/lists/" + id + "/upload").body()).contains("\"status\":\"UPLOADING\"",
                "\"received\":0", "\"size\":" + bytes.length);

        HttpResponse<String> first = chunk(id, 0, Arrays.copyOfRange(bytes, 0, CHUNK));
        assertThat(first.body()).contains("\"received\":" + CHUNK);
        // The same chunk again (its answer was lost): nothing changes.
        assertThat(chunk(id, 0, Arrays.copyOfRange(bytes, 0, CHUNK)).body()).contains("\"received\":" + CHUNK);
        // A chunk from too far ahead: refused, with where to go on from.
        HttpResponse<String> gap = chunk(id, CHUNK + 10, Arrays.copyOfRange(bytes, CHUNK + 10, CHUNK + 20));
        assertThat(gap.statusCode()).isEqualTo(409);
        assertThat(gap.body()).contains("\"code\":\"UPLOAD_OFFSET_MISMATCH\"", "\"received\":" + CHUNK);
        // The browser came back later: it asks where the upload stands and overlaps a little.
        assertThat(get("/api/v1/lists/" + id + "/upload").body()).contains("\"received\":" + CHUNK);
        int at = 2 * CHUNK - 100;
        HttpResponse<String> overlap = chunk(id, CHUNK - 100, Arrays.copyOfRange(bytes, CHUNK - 100, at));
        assertThat(overlap.body()).contains("\"received\":" + at);
        HttpResponse<String> last = chunk(id, at, Arrays.copyOfRange(bytes, at, bytes.length));
        assertThat(last.body()).contains("\"received\":" + bytes.length, "\"status\":\"MAPPING\"");
        // Nothing more is taken once the file is complete.
        assertThat(chunk(id, bytes.length, new byte[] {1}).statusCode()).isEqualTo(409);

        String body = importAndWait(id, null);
        assertThat(body).contains("\"status\":\"READY\"", "\"records\":7000", "\"totalLines\":7000", "\"invalid\":0");
        List<String> got = emails(id);
        assertThat(got).hasSize(7000).startsWith("user1@example.invalid").endsWith("user7000@example.invalid");
        assertThat(Files.exists(files.path(UUID.fromString(id)))).as("file deleted after the import").isFalse();
        assertThat(jdbc.queryForList("select action from activity_log where action like 'LIST%' order by id",
                String.class)).containsExactly("LIST_CREATED", "LIST_UPLOADED", "LIST_IMPORT_STARTED", "LIST_IMPORTED");
    }

    @Test
    void aChunkOverTheLimitIsRefusedAndNothingIsWritten() throws Exception {
        String id = id(create("Big chunk", "big.txt", 200_000, "").body());
        HttpResponse<String> res = chunk(id, 0, new byte[CHUNK + 1]);
        assertThat(res.statusCode()).isEqualTo(413);
        assertThat(get("/api/v1/lists/" + id + "/upload").body()).contains("\"received\":0");
    }

    @Test
    void theColumnGuessAndTheReportCountEveryLine() throws Exception {
        seedList("Older", "shared1@example.invalid", "Shared2@example.invalid");
        String csv = "Name;E-mail;City\n"
                + "Ann;ann@example.invalid;Montreal\n"
                + "\n"
                + "Bob;not an email;Laval\n"
                + "\"Smith; Jo\";SHARED1@example.invalid;\"Quebec\"\n"
                + "Cy;;Gatineau\n"
                + "Dee;ann@EXAMPLE.invalid;Sherbrooke\n"
                + "Eve;shared2@example.invalid;Levis\n";
        String id = upload("Report", csv, ",\"removeDuplicates\":false");
        String preview = get("/api/v1/lists/" + id + "/preview").body();
        assertThat(preview).contains("\"delimiter\":\";\"", "\"hasHeader\":true", "\"emailColumn\":1",
                "\"columns\":[\"Name\",\"E-mail\",\"City\"]", "\"emailsPerColumn\":[0,4,0]", "[\"Smith; Jo\"");

        String body = importAndWait(id, "{\"emailColumn\":1,\"hasHeader\":true}");
        // 6 lines (header and blank line not counted): 2 invalid, 4 imported, 1 repeated (kept), 2 in another list.
        assertThat(body).contains("\"totalLines\":6", "\"imported\":4", "\"invalid\":2", "\"duplicates\":1",
                "\"duplicatesRemoved\":false", "\"inOtherLists\":2", "\"records\":4", "\"parts\":1",
                "\"columns\":[\"Name\",\"E-mail\",\"City\"]");
        assertThat(emails(id)).containsExactly("ann@example.invalid", "SHARED1@example.invalid",
                "ann@example.invalid", "shared2@example.invalid");
        // Each member keeps its row's own cells.
        assertThat(get("/api/v1/lists/" + id + "/emails?q=shared1").body()).contains(
                "\"fields\":[\"Smith; Jo\",\"SHARED1@example.invalid\",\"Quebec\"]");
    }

    @Test
    void removeDuplicatesOnKeepsTheFirstOfEachAddressAndOffKeepsAll() throws Exception {
        String text = "a@example.invalid\nB@example.invalid\nA@Example.invalid\nc@example.invalid\nb@example.invalid\n"
                + "d@example.invalid\n";
        String on = upload("On", text, ",\"removeDuplicates\":true");
        assertThat(importAndWait(on, null)).contains("\"records\":4", "\"duplicates\":2", "\"duplicatesRemoved\":true",
                "\"totalLines\":6");
        assertThat(emails(on)).containsExactly("a@example.invalid", "B@example.invalid", "c@example.invalid",
                "d@example.invalid");
        assertThat(jdbc.queryForList("select seq from list_members m join lists l on l.id = m.list_id where "
                + "l.public_id = ?::uuid order by seq", Integer.class, on)).containsExactly(1, 2, 3, 4);

        String off = upload("Off", text, ",\"removeDuplicates\":false");
        assertThat(importAndWait(off, null)).contains("\"records\":6", "\"duplicates\":2", "\"duplicatesRemoved\":false",
                "\"inOtherLists\":4");
        assertThat(emails(off)).hasSize(6);
        // One contact per address, whatever the case and the list.
        assertThat(jdbc.queryForObject("select count(*) from contacts", Integer.class)).isEqualTo(4);
    }

    @Test
    void splitByMakesPartsOfThatSizeAfterDuplicatesAreRemoved() throws Exception {
        StringBuilder text = new StringBuilder();
        for (int i = 1; i <= 10; i++) {
            text.append("p").append(i).append("@example.invalid\n");
            if (i == 4) {
                text.append("p2@example.invalid\n");
            }
        }
        String id = upload("Split", text.toString(), ",\"removeDuplicates\":true,\"splitBy\":4");
        String body = importAndWait(id, null);
        assertThat(body).contains("\"records\":10", "\"parts\":3", "\"duplicates\":1",
                "\"partNo\":1,\"records\":4,\"firstSeq\":1,\"lastSeq\":4",
                "\"partNo\":2,\"records\":4,\"firstSeq\":5,\"lastSeq\":8",
                "\"partNo\":3,\"records\":2,\"firstSeq\":9,\"lastSeq\":10");
        assertThat(get("/api/v1/lists/" + id + "/emails?part=2").body()).contains("p5@", "p8@").doesNotContain("p4@",
                "p9@");
    }

    @Test
    void anInterruptedImportStartsAgainFromTheFileAfterARestart() throws Exception {
        String id = upload("Restart", "r1@example.invalid\nr2@example.invalid\nr3@example.invalid\nr1@example.invalid\n"
                + "r4@example.invalid\n", ",\"removeDuplicates\":true,\"splitBy\":2");
        // The backend died half-way: the list says IMPORTING, with some members and staging rows already written.
        long listId = jdbc.queryForObject("select id from lists where public_id = ?::uuid", Long.class, id);
        jdbc.update("update lists set status = 'IMPORTING', import_phase = 'SAVING', email_column = 0, has_header = "
                + "false where id = ?", listId);
        jdbc.update("insert into contacts (email, domain) values ('r1@example.invalid', 'example.invalid')");
        jdbc.update("insert into list_members (list_id, seq, part_no, contact_id, email) select ?, 1, 1, id, email "
                + "from contacts where email = 'r1@example.invalid'", listId);
        jdbc.update("insert into list_import_rows (list_id, seq, email, norm, domain) values (?, 1, "
                + "'r1@example.invalid', 'r1@example.invalid', 'example.invalid')", listId);

        importer.resumeAfterRestart();

        String body = waitFor(id, "\"status\":\"READY\"", "\"status\":\"FAILED\"");
        assertThat(body).contains("\"status\":\"READY\"", "\"records\":4", "\"duplicates\":1", "\"parts\":2");
        assertThat(emails(id)).containsExactly("r1@example.invalid", "r2@example.invalid", "r3@example.invalid",
                "r4@example.invalid");
        assertThat(jdbc.queryForObject("select count(*) from list_import_rows", Integer.class)).isZero();
    }

    @Test
    void aFileWithoutAnyValidAddressFailsWithAClearMessage() throws Exception {
        String id = upload("Nothing", "hello\nworld\n", "");
        String body = importAndWait(id, null);
        assertThat(body).contains("\"status\":\"FAILED\"", "No valid email address in the chosen column");
    }

    @Test
    void anUnclosedQuoteStopsTheImportWithTheLine() throws Exception {
        StringBuilder text = new StringBuilder("name,email\nAnn,ann@example.invalid\n\"Bob,bob@example.invalid\n");
        String id = upload("Quote", text.toString(), "");
        // The guess keeps the first line as header and column 1.
        String body = importAndWait(id, "{\"emailColumn\":1,\"hasHeader\":true}");
        assertThat(body).contains("\"status\":\"READY\"", "\"records\":1");
    }

    @Test
    void theFormIsCheckedBeforeAnythingIsWritten() throws Exception {
        assertThat(create("x", "list.xlsx", 10, "").statusCode()).isEqualTo(400);
        assertThat(create("", "list.csv", 10, "").body()).contains("\"field\":\"name\"");
        assertThat(create("x", "list.csv", 0, "").body()).contains("\"field\":\"fileSize\"");
        HttpResponse<String> big = create("x", "list.csv", 2 * 1024 * 1024, "");
        assertThat(big.statusCode()).isEqualTo(413);
        assertThat(big.body()).contains("1 MB");
        assertThat(create("x", "list.csv", 10, ",\"splitBy\":-1").body()).contains("\"field\":\"splitBy\"");
        assertThat(jdbc.queryForObject("select count(*) from lists", Integer.class)).isZero();
    }

    @Test
    void uploadingNeedsTheListsCreatePermission() throws Exception {
        String id = upload("Mine", "a@example.invalid\n", "");
        String viewer = member("LISTS:VIEW");
        assertThat(client.send("POST", "/api/v1/lists", viewer, "{\"name\":\"x\",\"fileName\":\"a.csv\","
                + "\"fileSize\":3}").statusCode()).isEqualTo(403);
        assertThat(chunk(viewer, id, 0, new byte[] {1}).statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/lists/" + id + "/preview", viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", "/api/v1/lists/" + id + "/import", viewer, "{}").statusCode()).isEqualTo(403);
        String creator = member("LISTS:CREATE");
        assertThat(client.send("GET", "/api/v1/lists/" + id + "/preview", creator, null).statusCode()).isEqualTo(200);
    }

    @Test
    void deletingAListThatWaitsForItsColumnDeletesItsFile() throws Exception {
        String id = upload("Waiting", "a@example.invalid\n", "");
        assertThat(Files.exists(files.path(UUID.fromString(id)))).isTrue();
        assertThat(client.send("DELETE", "/api/v1/lists/" + id, owner, null).statusCode()).isEqualTo(204);
        assertThat(Files.exists(files.path(UUID.fromString(id)))).isFalse();
    }
}

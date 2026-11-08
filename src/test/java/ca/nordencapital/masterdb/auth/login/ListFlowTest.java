package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** List management, job 1: the lists table, one list, parts, members, edit, delete, export, permissions. */
class ListFlowTest extends ListFlowTestBase {

    @Test
    void theTableSearchesFiltersAndSorts() throws Exception {
        seedList("Canada leads", "Gmail", "Canada", 0, null, null, "a@example.invalid", "b@example.invalid");
        seedList("US leads", "Outlook", "USA", 0, null, null, "c@example.invalid");
        seedList("Mixed", "Gmail", "USA", 0, null, null, "d@example.invalid", "e@example.invalid", "f@example.invalid");

        String all = get("/api/v1/lists?sort=records,desc").body();
        assertThat(all).contains("\"totalItems\":3");
        assertThat(all.indexOf("\"name\":\"Mixed\"")).isLessThan(all.indexOf("\"name\":\"Canada leads\""));
        assertThat(all.indexOf("\"name\":\"Canada leads\"")).isLessThan(all.indexOf("\"name\":\"US leads\""));

        assertThat(get("/api/v1/lists?esp=Gmail").body()).contains("\"totalItems\":2").doesNotContain("US leads");
        assertThat(get("/api/v1/lists?q=lead&country=USA").body()).contains("\"totalItems\":1", "US leads");
        assertThat(get("/api/v1/lists/facets").body()).contains("\"esp\":[\"Gmail\",\"Outlook\"]",
                "\"country\":[\"Canada\",\"USA\"]");
        assertThat(get("/api/v1/lists?sort=nope").statusCode()).isEqualTo(400);
    }

    @Test
    void oneListShowsItsPartsAndPagesThroughItsAddresses() throws Exception {
        String[] emails = new String[7];
        for (int i = 0; i < 7; i++) {
            emails[i] = "user" + (i + 1) + "@example.invalid";
        }
        String id = seedList("Split list", "", "", 3, null, null, emails);

        String detail = get("/api/v1/lists/" + id).body();
        assertThat(detail).contains("\"records\":7", "\"parts\":3", "\"status\":\"READY\"",
                "\"partNo\":1,\"records\":3,\"firstSeq\":1,\"lastSeq\":3",
                "\"partNo\":3,\"records\":1,\"firstSeq\":7,\"lastSeq\":7");

        String page = get("/api/v1/lists/" + id + "/emails?size=2&page=1").body();
        assertThat(page).contains("\"totalItems\":7", "\"totalPages\":4", "\"seq\":3,\"partNo\":1,"
                + "\"email\":\"user3@example.invalid\"", "\"seq\":4,\"partNo\":2");
        String part = get("/api/v1/lists/" + id + "/emails?part=2").body();
        assertThat(part).contains("\"totalItems\":3", "user4@", "user6@").doesNotContain("user3@", "user7@");
        assertThat(get("/api/v1/lists/" + id + "/emails?q=USER7").body()).contains("\"totalItems\":1", "user7@");
        assertThat(get("/api/v1/lists/" + id + "/emails?part=9").statusCode()).isEqualTo(400);
        assertThat(get("/api/v1/lists/00000000-0000-0000-0000-000000000000").statusCode()).isEqualTo(404);
    }

    @Test
    void detailsCanBeEditedAndTheChangeIsLogged() throws Exception {
        String id = seedList("Old name", "Gmail", "Canada", 0, null, null, "a@example.invalid");
        HttpResponse<String> res = client.send("PUT", "/api/v1/lists/" + id, owner,
                "{\"name\":\" New name \",\"esp\":\"Yahoo\",\"country\":\"Canada\",\"vertical\":\"Finance\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"name\":\"New name\"", "\"esp\":\"Yahoo\"", "\"vertical\":\"Finance\"");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'LIST_UPDATED'",
                String.class)).contains("Old name → New name", "Gmail → Yahoo").doesNotContain("country");

        HttpResponse<String> blank = client.send("PUT", "/api/v1/lists/" + id, owner, "{\"name\":\"  \"}");
        assertThat(blank.statusCode()).isEqualTo(400);
        assertThat(blank.body()).contains("\"field\":\"name\"");
    }

    @Test
    void deleteRemovesTheListButKeepsTheContacts() throws Exception {
        String a = seedList("First", "a@example.invalid", "shared@example.invalid");
        seedList("Second", "shared@example.invalid");
        HttpResponse<String> res = client.send("DELETE", "/api/v1/lists/" + a, owner, null);
        assertThat(res.statusCode()).isEqualTo(204);
        assertThat(get("/api/v1/lists/" + a).statusCode()).isEqualTo(404);
        assertThat(jdbc.queryForObject("select count(*) from list_members", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from contacts", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'LIST_DELETED'",
                String.class)).contains("\"records\": 2");
    }

    @Test
    void theExportGivesBackTheFilesOwnColumns() throws Exception {
        String id = seedList("Leads", "", "", 2, List.of("Name", "Email", "City"),
                List.of(List.of("Ann", "ann@example.invalid", "Montreal"), List.of("=cmd", "bob@example.invalid",
                        "Laval, QC"), List.of("Cy", "cy@example.invalid")),
                "ann@example.invalid", "bob@example.invalid", "cy@example.invalid");
        HttpResponse<String> all = get("/api/v1/lists/" + id + "/export");
        assertThat(all.statusCode()).isEqualTo(200);
        assertThat(all.headers().firstValue("Content-Disposition").orElse("")).contains("leads.csv");
        assertThat(all.body()).isEqualTo("﻿\"Name\",\"Email\",\"City\"\r\n"
                + "\"Ann\",\"ann@example.invalid\",\"Montreal\"\r\n"
                + "\"'=cmd\",\"bob@example.invalid\",\"Laval, QC\"\r\n"
                + "\"Cy\",\"cy@example.invalid\",\"\"\r\n");
        HttpResponse<String> part = get("/api/v1/lists/" + id + "/export?part=2");
        assertThat(part.body()).contains("cy@example.invalid").doesNotContain("ann@");
        assertThat(part.headers().firstValue("Content-Disposition").orElse("")).contains("leads-part-2.csv");
        assertThat(jdbc.queryForObject("select count(*) from activity_log where action = 'LIST_EXPORTED'",
                Integer.class)).isEqualTo(2);

        String plain = seedList("Plain", "x@example.invalid");
        assertThat(get("/api/v1/lists/" + plain + "/export").body()).isEqualTo("﻿\"email\"\r\n"
                + "\"x@example.invalid\"\r\n");
    }

    @Test
    void everyCallNeedsItsListsPermission() throws Exception {
        String id = seedList("Leads", "a@example.invalid");
        String none = member();
        assertThat(client.send("GET", "/api/v1/lists", none, null).statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/lists/" + id, none, null).statusCode()).isEqualTo(403);

        String viewer = member("LISTS:VIEW");
        assertThat(client.send("GET", "/api/v1/lists", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/api/v1/lists/" + id + "/emails", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("PUT", "/api/v1/lists/" + id, viewer, "{\"name\":\"x\"}").statusCode()).isEqualTo(403);
        assertThat(client.send("DELETE", "/api/v1/lists/" + id, viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/lists/" + id + "/export", viewer, null).statusCode()).isEqualTo(403);

        String editor = member("LISTS:EDIT", "LISTS:DELETE", "LISTS:EXPORT");
        assertThat(client.send("GET", "/api/v1/lists/" + id + "/export", editor, null).statusCode()).isEqualTo(200);
        assertThat(client.send("DELETE", "/api/v1/lists/" + id, editor, null).statusCode()).isEqualTo(204);
    }
}

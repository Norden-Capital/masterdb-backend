package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.testsupport.FakeDriveServer.Answer;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** List management, job 2: lists from a Google Drive link, against a fake Drive (never Google). */
class ListDriveFlowTest extends ListFlowTestBase {

    static final String FILE_ID = "1AbCdEfGhIjKlMnOpQrStUv";

    HttpResponse<String> fromDrive(String link) throws Exception {
        return post("/api/v1/lists", "{\"name\":\"From Drive\",\"source\":\"DRIVE\",\"driveUrl\":\"" + link + "\"}");
    }

    String startDrive(String link) throws Exception {
        HttpResponse<String> res = fromDrive(link);
        assertThat(res.statusCode()).as(res.body()).isEqualTo(201);
        assertThat(res.body()).contains("\"source\":\"DRIVE\"");
        return id(res.body());
    }

    @Test
    void aSharedFileIsDownloadedThenImported() throws Exception {
        DRIVE.on("drive.google.com", "/uc", Answer.redirect("https://drive.usercontent.google.com/download?id="
                + FILE_ID + "&export=download"));
        DRIVE.on("drive.usercontent.google.com", "/download", Answer.file("email,name\nd1@example.invalid,Dee\n"
                + "d2@example.invalid,Dan\n"));
        String id = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view?usp=sharing");
        String body = waitFor(id, "\"status\":\"MAPPING\"", "\"status\":\"FAILED\"");
        assertThat(body).contains("\"status\":\"MAPPING\"", "\"emailColumn\":0", "\"hasHeader\":true");
        assertThat(DRIVE.requests()).containsExactly("drive.google.com /uc?export=download&id=" + FILE_ID,
                "drive.usercontent.google.com /download?id=" + FILE_ID + "&export=download");
        assertThat(importAndWait(id, null)).contains("\"status\":\"READY\"", "\"records\":2");
    }

    @Test
    void googlesVirusScanPageIsAnsweredLikeDownloadAnyway() throws Exception {
        DRIVE.on("drive.google.com", "/uc", Answer.html("<html><body>Google Drive can't scan this file for viruses."
                + "<form id=\"download-form\" action=\"https://drive.usercontent.google.com/download\" method=\"get\">"
                + "<input type=\"submit\" id=\"uc-download-link\" value=\"Download anyway\"/>"
                + "<input type=\"hidden\" name=\"id\" value=\"" + FILE_ID + "\">"
                + "<input type=\"hidden\" name=\"export\" value=\"download\">"
                + "<input type=\"hidden\" name=\"confirm\" value=\"t\">"
                + "<input type=\"hidden\" name=\"uuid\" value=\"abc-123\"></form></body></html>"));
        DRIVE.on("drive.usercontent.google.com", "/download", Answer.file("big1@example.invalid\n"));
        String id = startDrive("https://drive.google.com/open?id=" + FILE_ID);
        assertThat(waitFor(id, "\"status\":\"MAPPING\"", "\"status\":\"FAILED\"")).contains("\"status\":\"MAPPING\"");
        assertThat(DRIVE.requests().get(1)).isEqualTo("drive.usercontent.google.com /download?id=" + FILE_ID
                + "&export=download&confirm=t&uuid=abc-123");
    }

    @Test
    void aGoogleSheetIsFetchedAsCsv() throws Exception {
        DRIVE.on("docs.google.com", "/spreadsheets/d/" + FILE_ID + "/export",
                Answer.file("Email\ns1@example.invalid\n"));
        String id = startDrive("https://docs.google.com/spreadsheets/d/" + FILE_ID + "/edit#gid=0");
        assertThat(waitFor(id, "\"status\":\"MAPPING\"", "\"status\":\"FAILED\"")).contains("\"status\":\"MAPPING\"");
        assertThat(DRIVE.requests()).containsExactly("docs.google.com /spreadsheets/d/" + FILE_ID
                + "/export?format=csv");
    }

    @Test
    void aPrivateFileSaysHowToShareIt() throws Exception {
        DRIVE.on("drive.google.com", "/uc", Answer.redirect("https://accounts.google.com/ServiceLogin?continue=x"));
        String id = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
        String body = waitFor(id, "\"status\":\"FAILED\"");
        assertThat(body).contains("Anyone with the link");
        assertThat(DRIVE.requests()).hasSize(1);

        DRIVE.reset();
        DRIVE.on("drive.google.com", "/uc", Answer.status(403));
        String second = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
        assertThat(waitFor(second, "\"status\":\"FAILED\"")).contains("Anyone with the link");

        DRIVE.reset();
        DRIVE.on("drive.google.com", "/uc", Answer.html("<html>Sign in - Google Accounts accounts.google.com</html>"));
        String third = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
        assertThat(waitFor(third, "\"status\":\"FAILED\"")).contains("Anyone with the link");
        assertThat(jdbc.queryForObject("select count(*) from activity_log where action = 'LIST_IMPORT_FAILED'",
                Integer.class)).isEqualTo(3);
    }

    @Test
    void onlyGoogleDriveLinksAreAccepted() throws Exception {
        for (String link : new String[] {"https://evil.example/file/d/" + FILE_ID, "ftp://drive.google.com/file/d/"
                + FILE_ID, "https://drive.google.com.evil.example/file/d/" + FILE_ID, "https://127.0.0.1/file/d/"
                + FILE_ID, "https://user@drive.google.com/file/d/" + FILE_ID, "https://drive.google.com:8443/file/d/"
                + FILE_ID, "https://drive.google.com/drive/folders/" + FILE_ID, "not a link", ""}) {
            HttpResponse<String> res = fromDrive(link);
            assertThat(res.statusCode()).as(link).isEqualTo(400);
            assertThat(res.body()).as(link).contains("\"field\":\"driveUrl\"");
        }
        assertThat(DRIVE.requests()).isEmpty();
        assertThat(jdbc.queryForObject("select count(*) from lists", Integer.class)).isZero();
    }

    @Test
    void redirectsAwayFromGoogleAreNeverFollowed() throws Exception {
        for (String target : new String[] {"https://169.254.169.254/latest/meta-data/", "http://drive.usercontent"
                + ".google.com/download", "https://evil.example/x", "https://drive.usercontent.google.com:8080/x",
                "https://googleusercontent.com.evil.example/x"}) {
            DRIVE.reset();
            DRIVE.on("drive.google.com", "/uc", Answer.redirect(target));
            String id = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
            assertThat(waitFor(id, "\"status\":\"FAILED\"")).as(target).contains("which MasterDB doesn");
            assertThat(DRIVE.requests()).as(target).hasSize(1);
        }
        // The virus-scan form can't point elsewhere either.
        DRIVE.reset();
        DRIVE.on("drive.google.com", "/uc", Answer.html("<form id=\"download-form\" action=\"https://evil.example/"
                + "download\"><input type=\"hidden\" name=\"id\" value=\"x\"></form>"));
        String id = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
        assertThat(waitFor(id, "\"status\":\"FAILED\"")).contains("evil.example");
        assertThat(DRIVE.requests()).hasSize(1);
    }

    @Test
    void aFileOverTheCapIsRefusedWhileDownloading() throws Exception {
        DRIVE.on("drive.google.com", "/uc", Answer.file("x".repeat(1024 * 1024 + 10)));
        String id = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
        assertThat(waitFor(id, "\"status\":\"FAILED\"")).contains("1 MB");
        DRIVE.reset();
        DRIVE.on("drive.google.com", "/uc", Answer.status(404));
        String missing = startDrive("https://drive.google.com/file/d/" + FILE_ID + "/view");
        assertThat(waitFor(missing, "\"status\":\"FAILED\"")).contains("exist");
    }
}

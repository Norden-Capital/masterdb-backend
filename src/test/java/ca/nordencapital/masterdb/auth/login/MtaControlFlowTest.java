package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** Server management job 5: MTA list and manager against the fake SSH server. */
class MtaControlFlowTest extends ServerFlowTestBase {

    static final String STATUS = "MASTERDB_MTA_STATUS\nSERVICE postfix active\nSERVICE dovecot active\n"
            + "SERVICE opendkim failed\nVERSION postfix 3.8.6\nVERSION dovecot 2.3.21 (47349e2482)\n"
            + "VERSION opendkim 2.11.0\nQUEUE 2\n";

    String server;
    String base;

    @BeforeEach
    void serverWithMta() throws Exception {
        String domain = addManual("mx.example");
        server = connectedServer("mx1");
        client.send("PUT", "/api/v1/servers/" + server, owner, "{\"name\":\"mx1\",\"ip\":\"127.0.0.1\",\"sshPort\":"
                + SSH.port() + ",\"expiresOn\":\"2027-03-01\",\"domainId\":\"" + domain + "\"}");
        jdbc.update("update servers set mta_installed_at = now(), mta_domain = 'mx.example', mta_webmail = false");
        base = "/api/v1/mta/servers/" + server;
        SSH.on("MASTERDB_MTA_STATUS", 0, STATUS);
    }

    @Test
    void theListShowsEachMtaAndRefreshReadsItOverSsh() throws Exception {
        assertThat(get("/api/v1/mta/servers").body()).contains("\"name\":\"mx1\"", "\"domain\":\"mx.example\"",
                "\"heloHost\":\"mail.mx.example\"").doesNotContain("\"status\"");
        HttpResponse<String> res = post(base + "/status", null);
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("{\"name\":\"postfix\",\"state\":\"active\"}",
                "{\"name\":\"opendkim\",\"state\":\"failed\"}", "\"postfix\":\"3.8.6\"",
                "\"dovecot\":\"2.3.21 (47349e2482)\"", "\"queue\":2", "\"checkedAt\":\"2026-11-07T09:00:03Z\"");
        assertThat(get("/api/v1/mta/servers").body()).contains("\"queue\":2", "\"opendkim\":\"2.11.0\"");
        assertThat(SSH.exchanges().getLast().command()).isEqualTo("bash -s");
    }

    @Test
    void serviceActionsRunSystemctlAndAreLogged() throws Exception {
        HttpResponse<String> restart = post(base + "/services/postfix/restart", null);
        assertThat(restart.statusCode()).as(restart.body()).isEqualTo(200);
        assertThat(restart.body()).contains("{\"name\":\"postfix\",\"state\":\"active\"}");
        assertThat(SSH.exchanges()).anyMatch(e -> e.stdin().equals("systemctl restart postfix\n"));

        post(base + "/services/all/stop", null);
        post(base + "/services/opendkim/reset", null);
        assertThat(SSH.exchanges()).anyMatch(e -> e.stdin().equals("systemctl stop opendkim postfix dovecot\n"))
                .anyMatch(e -> e.stdin().equals("systemctl reset-failed opendkim\n"));
        assertThat(jdbc.queryForList("select details->>'action' || ' ' || (details->>'service') from activity_log "
                + "where action = 'MTA_SERVICE_ACTION' order by id", String.class))
                .containsExactly("restart postfix", "stop all", "reset opendkim");

        int before = SSH.exchanges().size();
        assertThat(post(base + "/services/sshd/stop", null).statusCode()).isEqualTo(400);
        assertThat(post(base + "/services/postfix/reboot", null).statusCode()).isEqualTo(400);
        assertThat(SSH.exchanges()).hasSize(before);

        SSH.on("systemctl start dovecot", 1, "Job for dovecot.service failed. password=x1\n");
        HttpResponse<String> failed = post(base + "/services/dovecot/start", null);
        assertThat(failed.statusCode()).isEqualTo(424);
        assertThat(failed.body()).contains("systemctl start dovecot failed (exit 1)", "password=[hidden]");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'MTA_SERVICE_ACTION' "
                + "order by id desc limit 1", String.class)).contains("\"ok\": false");
    }

    @Test
    void logsQueueAndFlush() throws Exception {
        SSH.on("journalctl", 0, "2026-11-07T08:59:00+0000 mx1 postfix/smtpd[811]: connect from unknown\n"
                + "2026-11-07T08:59:01+0000 mx1 app: db_password=hunter2\n");
        HttpResponse<String> logs = get(base + "/logs?source=postfix&lines=50");
        assertThat(logs.statusCode()).as(logs.body()).isEqualTo(200);
        assertThat(logs.body()).contains("\"source\":\"postfix\"", "\"lines\":50", "connect from unknown",
                "db_password=[hidden]").doesNotContain("hunter2");
        assertThat(SSH.exchanges()).anyMatch(e -> e.stdin().equals("journalctl --no-pager -o short-iso -n 50 "
                + "-u 'postfix*'\n"));
        assertThat(get(base + "/logs?source=mail&lines=9999").body()).contains("\"lines\":500");
        assertThat(get(base + "/logs?source=/etc/shadow").statusCode()).isEqualTo(400);

        SSH.on("postqueue -j", 0, "{\"queue_name\":\"deferred\",\"queue_id\":\"4BXyz1\",\"arrival_time\":1794041000,"
                + "\"message_size\":1520,\"sender\":\"postmaster@mx.example\",\"recipients\":[{\"address\":"
                + "\"a@shaw.ca\",\"delay_reason\":\"connect to mx: Connection timed out\"}]}\n{\"queue_name\":"
                + "\"active\",\"queue_id\":\"4BXyz2\",\"arrival_time\":1794041060,\"message_size\":900,\"sender\":\"\","
                + "\"recipients\":[]}\n");
        String queue = get(base + "/queue").body();
        assertThat(queue).contains("\"count\":2", "\"queueId\":\"4BXyz1\"", "\"queue\":\"deferred\"",
                "\"recipients\":1", "\"reason\":\"connect to mx: Connection timed out\"");
        HttpResponse<String> flushed = post(base + "/queue/flush", null);
        assertThat(flushed.statusCode()).isEqualTo(200);
        assertThat(SSH.exchanges()).anyMatch(e -> e.stdin().equals("postqueue -f\n"));
        assertThat(jdbc.queryForObject("select count(*) from activity_log where action = 'MTA_QUEUE_FLUSHED'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void removingFromTheListChangesNothingOnTheServer() throws Exception {
        int before = SSH.exchanges().size();
        assertThat(client.send("DELETE", base, owner, null).statusCode()).isEqualTo(204);
        assertThat(get("/api/v1/mta/servers").body()).isEqualTo("[]");
        assertThat(SSH.exchanges()).hasSize(before);
        assertThat(post(base + "/status", null).statusCode()).isEqualTo(409);
        assertThat(jdbc.queryForObject("select count(*) from activity_log where action = 'MTA_REMOVED'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void aBlockedServerIsNotTouched() throws Exception {
        SSH.newHostKey();
        HttpResponse<String> res = post(base + "/status", null);
        assertThat(res.statusCode()).isEqualTo(409);
        assertThat(res.body()).contains("\"code\":\"SERVER_HOST_KEY_CHANGED\"");
        assertThat(get("/api/v1/servers/" + server).body()).contains("\"connectionStatus\":\"KEY_CHANGED\"");
        assertThat(post(base + "/services/postfix/stop", null).statusCode()).isEqualTo(409);
    }

    @Test
    void permissionsAreChecked() throws Exception {
        String none = member("SERVERS:VIEW", "SERVERS:RUN");
        assertThat(client.send("GET", "/api/v1/mta/servers", none, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", base + "/services/postfix/stop", none, null).statusCode()).isEqualTo(403);

        String viewer = member("MTA:VIEW");
        assertThat(client.send("GET", "/api/v1/mta/servers", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("POST", base + "/status", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", base + "/queue", viewer, null).statusCode()).isEqualTo(200);
        int before = SSH.exchanges().size();
        assertThat(client.send("POST", base + "/services/postfix/stop", viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", base + "/queue/flush", viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("DELETE", base, viewer, null).statusCode()).isEqualTo(403);
        assertThat(SSH.exchanges()).hasSize(before);

        String runner = member("MTA:RUN");
        assertThat(client.send("POST", base + "/services/postfix/restart", runner, null).statusCode()).isEqualTo(200);
        assertThat(client.send("DELETE", base, runner, null).statusCode()).isEqualTo(403);
    }
}

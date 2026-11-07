package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.mta.MtaControlService.QueueView;
import ca.nordencapital.masterdb.mta.MtaControlService.ServiceState;
import ca.nordencapital.masterdb.mta.MtaControlService.Status;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class MtaControlParseTest {

    @Test
    void statusLinesAreReadStrictly() {
        Status s = MtaControlService.parseStatus("MASTERDB_MTA_STATUS\nSERVICE postfix active\nSERVICE dovecot "
                + "weird-state\nSERVICE sshd active\nVERSION postfix 3.6.4\nQUEUE -1\n");
        assertThat(s.services()).containsExactly(new ServiceState("postfix", "active"),
                new ServiceState("dovecot", "unknown"), new ServiceState("opendkim", "unknown"));
        assertThat(s.versions()).containsOnlyKeys("postfix");
        assertThat(s.queue()).isNull();
        assertThat(MtaControlService.parseStatus("bash: line 1: systemctl: command not found")).isNull();
    }

    @Test
    void theQueueIsCountedFromPostqueueJson() {
        QueueView q = MtaControlService.parseQueue("{\"queue_name\":\"deferred\",\"queue_id\":\"A1\","
                + "\"arrival_time\":1794041000,\"message_size\":10,\"sender\":\"s@x.example\",\"recipients\":[]}\n"
                + "postqueue: warning: something\n{broken\n", Instant.EPOCH);
        assertThat(q.count()).isEqualTo(2);
        assertThat(q.entries()).hasSize(1);
        assertThat(q.entries().getFirst().arrivedAt()).isEqualTo(Instant.ofEpochSecond(1794041000));
        assertThat(MtaControlService.parseQueue("", Instant.EPOCH).count()).isZero();
    }
}

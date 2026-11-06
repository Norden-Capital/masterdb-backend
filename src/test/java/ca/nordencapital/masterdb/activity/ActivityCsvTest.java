package ca.nordencapital.masterdb.activity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ActivityCsvTest {

    @Test
    void cellsAreQuotedAndFormulasDefused() {
        assertThat(ActivityController.csv(null)).isEmpty();
        assertThat(ActivityController.csv("plain")).isEqualTo("\"plain\"");
        assertThat(ActivityController.csv("say \"hi\", ok")).isEqualTo("\"say \"\"hi\"\", ok\"");
        for (String formula : new String[] {"=1+1", "+cmd", "-2", "@SUM(A1)", "\tx"}) {
            assertThat(ActivityController.csv(formula)).as(formula).startsWith("\"'");
        }
    }
}

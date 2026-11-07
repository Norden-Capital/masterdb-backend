package ca.nordencapital.masterdb.validation.bulk;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** What a pasted list becomes: one address per line, CSV rows allowed, duplicates and bad lines counted. */
class BulkPasteTest {

    @Test
    void linesCsvRowsDuplicatesAndBadLines() {
        var p = BulkJobService.parse("email,name\r\njane@example.com,Jane\n\"Bob@Example.com\";Bob\n\n"
                + "JANE@example.com\nnot an email\t\nann@example.com\r");
        assertThat(p.emails()).containsExactly("jane@example.com", "Bob@example.com", "ann@example.com");
        assertThat(p.duplicates()).isEqualTo(1);
        // The header row and "not an email".
        assertThat(p.invalid()).isEqualTo(2);
    }

    @Test
    void emptyPaste() {
        var p = BulkJobService.parse("  \n\n");
        assertThat(p.emails()).isEmpty();
        assertThat(p.invalid()).isZero();
    }
}

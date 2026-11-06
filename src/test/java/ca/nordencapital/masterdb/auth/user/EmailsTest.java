package ca.nordencapital.masterdb.auth.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class EmailsTest {

    @Test
    void normalizeTrimsAndLowercases() {
        assertThat(Emails.normalize("  Jane.Doe@Example.COM\t")).isEqualTo("jane.doe@example.com");
        assertThat(Emails.normalize(null)).isNull();
    }

    @Test
    void maskKeepsFirstLetterAndDomain() {
        assertThat(Emails.mask("Jane.Doe@NordenCapital.ca")).isEqualTo("j***@nordencapital.ca");
        assertThat(Emails.mask("a@b.co")).isEqualTo("a***@b.co");
        assertThat(Emails.mask("not-an-email")).isEqualTo("***");
        assertThat(Emails.mask("@domain.ca")).isEqualTo("***");
        assertThat(Emails.mask(null)).isEqualTo("***");
    }

    @ParameterizedTest
    @ValueSource(strings = {"jane@example.com", " Jane@Example.COM ", "a.b+tag@sub.example.co.uk"})
    void validAddresses(String email) {
        assertThat(Emails.isValid(email)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "jane", "jane@", "@example.com", "jane@example", "ja ne@example.com",
            "jane@@example.com", "jane@example.com."})
    void invalidAddresses(String email) {
        assertThat(Emails.isValid(email)).isFalse();
    }

    @Test
    void tooLongIsInvalid() {
        assertThat(Emails.isValid("a".repeat(250) + "@x.ca")).isFalse();
    }
}

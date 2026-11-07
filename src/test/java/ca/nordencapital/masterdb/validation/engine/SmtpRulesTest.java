package ca.nordencapital.masterdb.validation.engine;

import ca.nordencapital.masterdb.validation.Category;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** One line per reply: the rule table of the old app plus the agreed fixes. */
class SmtpRulesTest {

    static final String GMAIL = "gmail-smtp-in.l.google.com";
    static final String MS = "contoso-com.mail.protection.outlook.com";

    @ParameterizedTest(name = "{0} {1} at {2} -> {3}")
    @CsvSource(delimiter = '|', textBlock = """
            550 | 5.1.1 The email account that you tried to reach does not exist          | gmail-smtp-in.l.google.com | BOUNCE
            550 | 5.2.1 The email account that you tried to reach is disabled             | gmail-smtp-in.l.google.com | BOUNCE
            550 | 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found            | contoso-com.mail.protection.outlook.com | BOUNCE
            550 | 5.5.0 Requested action not taken: mailbox unavailable (S2017062302)   | contoso-com.mail.protection.outlook.com | BOUNCE
            550 | 5.5.0 Requested action not taken: mailbox unavailable (S2017062302)   | mx.other.test | UNKNOWN
            554 | delivery error: dd This user doesn't have a yahoo.com account          | mta5.am0.yahoodns.net | UNKNOWN
            550 | No such user here                                                       | mx.other.test | BOUNCE
            552 | 5.2.2 The email account that you tried to reach is over quota           | gmail-smtp-in.l.google.com | SOFT_BOUNCE
            452 | 4.2.2 Mailbox full                                                      | mx.other.test | SOFT_BOUNCE
            550 | 5.7.1 Service unavailable; client host blocked using Spamhaus          | mx.other.test | REJECT
            554 | 5.7.1 Message rejected due to content policy                            | mx.other.test | REJECT
            550 | 5.7.606 Access denied, banned sending IP                                | contoso-com.mail.protection.outlook.com | REJECT
            421 | 4.7.28 Unusual rate of unsolicited mail. Try again later                | gmail-smtp-in.l.google.com | UNKNOWN
            450 | 4.2.1 The user you are trying to contact is receiving mail too quickly  | gmail-smtp-in.l.google.com | UNKNOWN
            451 | 4.3.0 Temporary server error                                            | mx.other.test | UNKNOWN
            550 | Something went wrong                                                    | mx.other.test | UNKNOWN
            """)
    void refusal(int code, String text, String mx, Category expected) {
        assertThat(SmtpRules.refusal(code, code + " " + text, mx)).isEqualTo(expected);
    }

    @Test
    void slowDownAndBlockedDriveThePacing() {
        assertThat(SmtpRules.rateLimited(421, "421 Service not available")).isTrue();
        assertThat(SmtpRules.rateLimited(450, "450 4.7.1 Greylisted, please try again later")).isTrue();
        assertThat(SmtpRules.rateLimited(550, "550 5.1.1 User unknown")).isFalse();
        assertThat(SmtpRules.providerBlocked(554, "554 Your IP is on our blacklist")).isTrue();
        assertThat(SmtpRules.providerBlocked(450, "450 blacklist")).isFalse();
    }

    @Test
    void catchAllControls() {
        assertThat(SmtpRules.control(250, "250 ok", 250, "250 ok", GMAIL)).isEqualTo(SmtpRules.Control.CATCH_ALL);
        assertThat(SmtpRules.control(550, "550 5.1.1 no", 550, "550 5.1.1 no", GMAIL))
                .isEqualTo(SmtpRules.Control.NOT_CATCH_ALL);
        assertThat(SmtpRules.control(550, "550 5.5.0 mailbox unavailable (S2017062302)", 550,
                "550 5.5.0 mailbox unavailable (S2017062302)", MS)).isEqualTo(SmtpRules.Control.NOT_CATCH_ALL);
        assertThat(SmtpRules.control(250, "250 ok", 450, "450 try later", GMAIL))
                .isEqualTo(SmtpRules.Control.UNKNOWN);
    }

    @Test
    void syntax() {
        assertThat(EmailAddress.parse(" <Jane.Doe@Example.COM> ")).hasValueSatisfying(e -> {
            assertThat(e.address()).isEqualTo("Jane.Doe@example.com");
            assertThat(e.normalized()).isEqualTo("jane.doe@example.com");
        });
        assertThat(EmailAddress.parse("jane@bücher.de")).hasValueSatisfying(e ->
                assertThat(e.domain()).isEqualTo("xn--bcher-kva.de"));
        for (String bad : new String[] {"", "jane", "@x.com", "a@@x.com", ".a@x.com", "a..b@x.com", "a@x",
                "a b@x.com", "a@x.c0m", "a@-x.com", "ä@x.com"}) {
            assertThat(EmailAddress.parse(bad)).as(bad).isEmpty();
        }
    }
}

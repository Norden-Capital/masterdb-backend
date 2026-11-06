package ca.nordencapital.masterdb.status;

import ca.nordencapital.testsupport.OpenWebSecurity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Properties;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Web slice only: no database, no full context. */
@WebMvcTest(StatusController.class)
@Import({StatusControllerTest.Fixtures.class, OpenWebSecurity.class})
class StatusControllerTest {

    @TestConfiguration
    static class Fixtures {
        @Bean
        Clock clock() {
            return Clock.fixed(Instant.parse("2026-11-06T12:00:00Z"), ZoneOffset.UTC);
        }

        @Bean
        BuildProperties buildProperties() {
            Properties p = new Properties();
            p.setProperty("version", "1.2.3-test");
            return new BuildProperties(p);
        }
    }

    @Autowired
    MockMvc mvc;

    @Test
    void returnsServiceStatusVersionAndIsoTime() throws Exception {
        mvc.perform(get("/api/v1/status"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.service").value("masterdb-backend"))
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.version").value("1.2.3-test"))
                .andExpect(jsonPath("$.time").value("2026-11-06T12:00:00Z"));
    }
}

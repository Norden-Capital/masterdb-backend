package ca.nordencapital.masterdb.config;

import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Docs switched on by the {@code local} profile, which ./mvnw spring-boot:run uses. */
@SpringBootTest
@ActiveProfiles("local")
@AutoConfigureMockMvc
class ApiDocsEnabledTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @Autowired
    MockMvc mvc;

    @Test
    void swaggerUiIsServedAtApiDocsWithItsAssets() throws Exception {
        mvc.perform(get("/api/docs"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/api/v3/api-docs/swagger-config")));
        mvc.perform(get("/api/v3/api-docs/swagger-config")).andExpect(status().isOk());
        mvc.perform(get("/swagger-ui/swagger-ui-bundle.js")).andExpect(status().isOk());
    }

    @Test
    void openApiJsonListsTheApi() throws Exception {
        mvc.perform(get("/api/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("MasterDB API"))
                .andExpect(jsonPath("$.paths['/api/v1/status']").exists())
                .andExpect(jsonPath("$.paths['/api/docs']").doesNotExist());
    }

    @Test
    void openApiDocumentsTheProblemDetailErrorResponse() throws Exception {
        mvc.perform(get("/api/v3/api-docs"))
                .andExpect(jsonPath("$.components.schemas.ProblemDetail.properties.code.enum").isArray())
                .andExpect(jsonPath("$.components.schemas.ProblemDetail.properties.requestId").exists())
                .andExpect(jsonPath("$.components.schemas.FieldViolation").exists())
                .andExpect(jsonPath("$.paths['/api/v1/status'].get.responses.default.content['application/problem+json']"
                        + ".schema['$ref']").value("#/components/schemas/ProblemDetail"));
    }
}

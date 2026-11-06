package ca.nordencapital.masterdb.web;

import ca.nordencapital.testsupport.ProbeController;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The API conventions (error shape, request id, request log, pagination, JSON
 * settings) exercised through test-only endpoints. Web slice: no database.
 */
@WebMvcTest(ProbeController.class)
@Import(ProbeController.class)
@ExtendWith(OutputCaptureExtension.class)
class ApiConventionsTest {

    private static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final String ISO_UTC = "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z";

    @Autowired
    MockMvc mvc;

    /** The parts every error body has, whatever the error. */
    static ResultMatcher problem(int status, String code) {
        return result -> {
            status().is(status).match(result);
            content().contentType(MediaType.APPLICATION_PROBLEM_JSON).match(result);
            jsonPath("$.status").value(status).match(result);
            jsonPath("$.code").value(code).match(result);
            jsonPath("$.title").isString().match(result);
            jsonPath("$.detail").isString().match(result);
            jsonPath("$.timestamp", matchesPattern(ISO_UTC)).match(result);
            String id = result.getResponse().getHeader("X-Request-Id");
            assertThat(id).isNotBlank();
            jsonPath("$.requestId").value(id).match(result);
        };
    }

    @Nested
    class Errors {

        @Test
        void invalidBodyIsValidationFailedWithFieldErrors() throws Exception {
            mvc.perform(post("/probe/body").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\":\"not-an-email\",\"count\":0}"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.instance").value("/probe/body"))
                    .andExpect(jsonPath("$.errors", hasSize(2)))
                    .andExpect(jsonPath("$.errors[?(@.field=='email')].message").exists())
                    .andExpect(jsonPath("$.errors[?(@.field=='count')].message").exists())
                    .andExpect(content().string(not(containsString("not-an-email"))));
        }

        @Test
        void invalidQueryParamIsValidationFailed() throws Exception {
            mvc.perform(get("/probe/param").param("count", "50"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("count"))
                    .andExpect(jsonPath("$.errors[0].message").isString());
        }

        @Test
        void malformedJsonIs400WithoutEchoingTheInput() throws Exception {
            mvc.perform(post("/probe/body").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\": \"jane@example.com\", "))
                    .andExpect(problem(400, "MALFORMED_JSON"))
                    .andExpect(content().string(not(containsString("jane@example.com"))));
        }

        @Test
        void typeMismatchIsValidationFailed() throws Exception {
            mvc.perform(get("/probe/param").param("count", "jane@example.com"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("count"))
                    .andExpect(jsonPath("$.errors[0].message").value("must be a valid int"))
                    .andExpect(content().string(not(containsString("jane@example.com"))));
        }

        @Test
        void missingParamIsValidationFailed() throws Exception {
            mvc.perform(get("/probe/param"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("count"))
                    .andExpect(jsonPath("$.errors[0].message").value("is required"));
        }

        @Test
        void unknownRouteIs404() throws Exception {
            mvc.perform(get("/api/v1/does-not-exist"))
                    .andExpect(problem(404, "NOT_FOUND"))
                    .andExpect(jsonPath("$.detail").value("The requested resource was not found."));
        }

        @Test
        void wrongMethodIs405WithAllowHeader() throws Exception {
            mvc.perform(delete("/probe/param"))
                    .andExpect(problem(405, "METHOD_NOT_ALLOWED"))
                    .andExpect(header().string("Allow", containsString("GET")));
        }

        @Test
        void unsupportedMediaTypeIs415() throws Exception {
            mvc.perform(post("/probe/body").contentType(MediaType.TEXT_PLAIN).content("hello"))
                    .andExpect(problem(415, "UNSUPPORTED_MEDIA_TYPE"));
        }

        @Test
        void notFoundExceptionIs404WithItsMessage() throws Exception {
            mvc.perform(get("/probe/not-found"))
                    .andExpect(problem(404, "NOT_FOUND"))
                    .andExpect(jsonPath("$.detail").value("Contact 42 was not found."));
        }

        @Test
        void conflictExceptionIs409() throws Exception {
            mvc.perform(get("/probe/conflict"))
                    .andExpect(problem(409, "CONFLICT"))
                    .andExpect(jsonPath("$.detail").value("An import is already running."));
        }

        @Test
        void badRequestExceptionIs400() throws Exception {
            mvc.perform(get("/probe/bad-request"))
                    .andExpect(problem(400, "BAD_REQUEST"))
                    .andExpect(jsonPath("$.detail").value("The file is empty."))
                    .andExpect(jsonPath("$.errors").doesNotExist());
        }

        @Test
        void unexpectedExceptionIs500WithoutLeakingButIsLogged(CapturedOutput output) throws Exception {
            MvcResult result = mvc.perform(get("/probe/boom"))
                    .andExpect(problem(500, "INTERNAL_ERROR"))
                    .andExpect(jsonPath("$.detail").value(
                            "An unexpected error occurred. Quote the requestId when reporting it."))
                    .andReturn();
            String body = result.getResponse().getContentAsString();
            assertThat(body).doesNotContain("hunter2", "jane.doe", "IllegalStateException", "ProbeController",
                    "at ca.");
            String id = result.getResponse().getHeader("X-Request-Id");
            assertThat(output).contains("Request failed with 500 (requestId=" + id + ")")
                    .contains("IllegalStateException");
        }
    }

    @Nested
    class RequestIds {

        @Test
        void safeIncomingIdIsEchoed() throws Exception {
            mvc.perform(get("/probe/not-found").header("X-Request-Id", "frontend-abc-123"))
                    .andExpect(header().string("X-Request-Id", "frontend-abc-123"))
                    .andExpect(jsonPath("$.requestId").value("frontend-abc-123"));
        }

        @Test
        void missingIdIsGenerated() throws Exception {
            mvc.perform(get("/probe/json"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-Request-Id", matchesPattern(UUID)));
        }

        @Test
        void unsafeIdsAreReplaced() throws Exception {
            for (String unsafe : new String[] {"a b", "abc\r\nInjected: yes", "<script>", "x".repeat(65), "a_b", ""}) {
                mvc.perform(get("/probe/json").header("X-Request-Id", unsafe))
                        .andExpect(header().string("X-Request-Id", matchesPattern(UUID)));
            }
            mvc.perform(get("/probe/json").header("X-Request-Id", "x".repeat(64)))
                    .andExpect(header().string("X-Request-Id", "x".repeat(64)));
        }
    }

    @Nested
    class RequestLog {

        @Test
        void oneLinePerRequestWithPathOnly(CapturedOutput output) throws Exception {
            mvc.perform(get("/probe/param").param("count", "3").param("email", "jane@example.com")
                            .header("X-Request-Id", "log-test-1"))
                    .andExpect(status().isOk());
            assertThat(output).containsPattern("GET /probe/param 200 \\d+ms requestId=log-test-1")
                    .contains("[log-test-1]")
                    .doesNotContain("jane@example.com")
                    .doesNotContain("count=3");
        }

        @Test
        void healthChecksAreNotLogged(CapturedOutput output) throws Exception {
            mvc.perform(get("/actuator/health").header("X-Request-Id", "health-probe-1"));
            mvc.perform(get("/actuator/health/liveness").header("X-Request-Id", "health-probe-2"));
            assertThat(output).doesNotContain("requestId=health-probe-1").doesNotContain("requestId=health-probe-2");
        }
    }

    @Nested
    class Pagination {

        @Test
        void defaultsAreFirstPageOf25WithDefaultSort() throws Exception {
            mvc.perform(get("/probe/page"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.page").value(0))
                    .andExpect(jsonPath("$.size").value(25))
                    .andExpect(jsonPath("$.totalItems").value(1234))
                    .andExpect(jsonPath("$.totalPages").value(50))
                    .andExpect(jsonPath("$.items[0]").value("createdAt,desc"));
        }

        @Test
        void sizeIsClampedTo1To100() throws Exception {
            mvc.perform(get("/probe/page").param("size", "1000"))
                    .andExpect(jsonPath("$.size").value(100))
                    .andExpect(jsonPath("$.totalPages").value(13));
            mvc.perform(get("/probe/page").param("size", "0")).andExpect(jsonPath("$.size").value(1));
            mvc.perform(get("/probe/page").param("size", "-5")).andExpect(jsonPath("$.size").value(1));
        }

        @Test
        void pageSlicesAndMapsRows() throws Exception {
            mvc.perform(get("/probe/rows").param("page", "1").param("size", "20"))
                    .andExpect(jsonPath("$.items", hasSize(10)))
                    .andExpect(jsonPath("$.items[0]").value(200))
                    .andExpect(jsonPath("$.page").value(1))
                    .andExpect(jsonPath("$.totalItems").value(30))
                    .andExpect(jsonPath("$.totalPages").value(2));
        }

        @Test
        void whitelistedSortsAreApplied() throws Exception {
            mvc.perform(get("/probe/page").param("sort", "name,desc").param("sort", "createdAt"))
                    .andExpect(jsonPath("$.items[0]").value("name,desc"))
                    .andExpect(jsonPath("$.items[1]").value("createdAt,asc"));
            mvc.perform(get("/probe/page").param("sort", "name,DESC"))
                    .andExpect(jsonPath("$.items", hasSize(1)))
                    .andExpect(jsonPath("$.items[0]").value("name,desc"));
        }

        @Test
        void unknownSortFieldIsValidationFailed() throws Exception {
            mvc.perform(get("/probe/page").param("sort", "passwordHash,asc"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("sort"))
                    .andExpect(jsonPath("$.errors[0].message").value("must be field or field,asc|desc with field one of: createdAt, name"));
        }

        @Test
        void badSortDirectionIsValidationFailed() throws Exception {
            mvc.perform(get("/probe/page").param("sort", "name,sideways"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("sort"));
        }

        @Test
        void negativePageAndNonNumericSizeAreValidationFailed() throws Exception {
            mvc.perform(get("/probe/page").param("page", "-1"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("page"));
            ResultActions bad = mvc.perform(get("/probe/page").param("size", "lots"))
                    .andExpect(problem(400, "VALIDATION_FAILED"))
                    .andExpect(jsonPath("$.errors[0].field").value("size"));
            assertThat(bad.andReturn().getResponse().getContentAsString()).doesNotContain("lots");
        }
    }

    @Nested
    class Json {

        @Test
        void datesAreIsoStringsAndNullsAreOmitted() throws Exception {
            mvc.perform(get("/probe/json"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.at").value("2026-11-06T12:00:00Z"))
                    .andExpect(jsonPath("$.name").value("x"))
                    .andExpect(jsonPath("$.nothing").doesNotExist())
                    .andExpect(content().string(not(containsString("null"))));
        }
    }
}

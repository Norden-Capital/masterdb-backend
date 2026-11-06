package ca.nordencapital.masterdb.web.error;

import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import ca.nordencapital.testsupport.OpenWebSecurity;
import org.springframework.context.annotation.Import;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The container's /error forward (errors that never reached a controller),
 * simulated by setting the attributes Tomcat sets.
 */
@WebMvcTest(ProblemErrorController.class)
@Import(OpenWebSecurity.class)
@ExtendWith(OutputCaptureExtension.class)
class ProblemErrorControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void serverErrorFromAFilterIsGenericProblemJsonAndLogged(CapturedOutput output) throws Exception {
        MvcResult result = mvc.perform(get("/error")
                        .accept(MediaType.TEXT_HTML)
                        // set by RequestIdFilter on the original dispatch; request attributes survive the forward
                        .requestAttr(RequestIdFilter.ATTRIBUTE, "err-page-1")
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 500)
                        .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/api/v1/contacts")
                        .requestAttr(RequestDispatcher.ERROR_EXCEPTION,
                                new IllegalStateException("jdbc:postgresql://secret-host password=hunter2")))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
                .andExpect(jsonPath("$.instance").value("/api/v1/contacts"))
                .andExpect(jsonPath("$.requestId").value("err-page-1"))
                .andExpect(jsonPath("$.timestamp").isString())
                .andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("hunter2", "secret-host", "Illegal");
        assertThat(output).contains("Request failed with 500 (requestId=err-page-1)").contains("hunter2");
    }

    @Test
    void clientErrorKeepsItsStatus() throws Exception {
        mvc.perform(get("/error").requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 413))
                .andExpect(status().is(413))
                .andExpect(jsonPath("$.code").value("CONTENT_TOO_LARGE"))
                .andExpect(jsonPath("$.detail").value("Content Too Large"));
    }

    @Test
    void openingErrorDirectlyIs404() throws Exception {
        mvc.perform(get("/error"))
                .andExpect(status().isNotFound())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }
}

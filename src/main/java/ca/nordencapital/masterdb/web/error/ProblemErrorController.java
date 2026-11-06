package ca.nordencapital.masterdb.web.error;

import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.UUID;

/**
 * Replaces Spring Boot's {@code /error} page (BasicErrorController backs off
 * when another {@link ErrorController} exists), so errors that never reach
 * the {@link GlobalExceptionHandler} also answer in problem+json: exceptions
 * thrown in servlet filters, {@code response.sendError(...)}, container-level
 * errors. Always JSON, whatever the {@code Accept} header says.
 */
@Hidden
@RestController
public class ProblemErrorController implements ErrorController {

    private static final Logger log = LoggerFactory.getLogger(ProblemErrorController.class);

    @RequestMapping("${server.error.path:${error.path:/error}}")
    public ResponseEntity<ProblemDetail> error(HttpServletRequest request, HttpServletResponse response) {
        HttpStatusCode status = status(request);
        String requestId = requestId(request, response);

        Object error = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        if (status.is5xxServerError()) {
            MDC.put(RequestIdFilter.MDC_KEY, requestId);
            try {
                log.error("Request failed with {} (requestId={})", status.value(), requestId,
                        error instanceof Throwable t ? t : null);
            } finally {
                MDC.remove(RequestIdFilter.MDC_KEY);
            }
        }

        String detail = status.value() == 404 ? ProblemDetails.NOT_FOUND_DETAIL : reason(status);
        ErrorCode code = ErrorCode.fromStatus(status);
        // A filter that refused the request may have named its own code and detail.
        if (request.getAttribute(ProblemDetails.CODE_ATTRIBUTE) instanceof ErrorCode own) {
            code = own;
            if (request.getAttribute(ProblemDetails.DETAIL_ATTRIBUTE) instanceof String ownDetail) {
                detail = ownDetail;
            }
        }
        ProblemDetail problem = ProblemDetails.of(status, code, detail);
        Object uri = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        if (uri instanceof String path) {
            try {
                problem.setInstance(URI.create(path));
            } catch (IllegalArgumentException ignored) {
                // a path that is not a valid URI is simply left out
            }
        }
        ProblemDetails.complete(problem, requestId);
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
    }

    /** No status attribute means someone opened /error directly: treat it as an unknown page. */
    private static HttpStatusCode status(HttpServletRequest request) {
        Object code = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if (code instanceof Integer value && value >= 400 && value <= 599) {
            return HttpStatusCode.valueOf(value);
        }
        return HttpStatus.NOT_FOUND;
    }

    private static String reason(HttpStatusCode status) {
        HttpStatus known = HttpStatus.resolve(status.value());
        return known != null ? known.getReasonPhrase() : "Request failed";
    }

    private static String requestId(HttpServletRequest request, HttpServletResponse response) {
        String id = RequestIdFilter.get(request);
        if (id == null) {
            id = response.getHeader(RequestIdFilter.HEADER);
        }
        if (id == null) {
            id = UUID.randomUUID().toString();
            response.setHeader(RequestIdFilter.HEADER, id);
        }
        return id;
    }
}

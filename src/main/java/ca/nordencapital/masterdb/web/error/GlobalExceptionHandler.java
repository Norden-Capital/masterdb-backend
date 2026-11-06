package ca.nordencapital.masterdb.web.error;

import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.TypeMismatchException;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.validation.method.ParameterErrors;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns every exception thrown while handling a request into the shared
 * problem+json error body (see {@link ProblemDetails}).
 *
 * <p>Spring's own MVC exceptions (405, 415, 406, ...) go through
 * {@link ResponseEntityExceptionHandler}; every one of them ends in
 * {@link #handleExceptionInternal}, which adds code, timestamp and requestId.
 * Validation-type 400s are rewritten into {@code VALIDATION_FAILED} with an
 * {@code errors} list. Anything unknown is a 500 whose body says nothing about
 * the cause; the full exception is logged with the requestId.
 *
 * <p>Rejected values are never echoed back or logged: they may be emails.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ---- the app's own exceptions ------------------------------------------------

    @ExceptionHandler(ApiException.class)
    ResponseEntity<Object> handleApiException(ApiException ex, WebRequest request) {
        ProblemDetail problem = ProblemDetails.of(ex.getStatus(), ex.getCode(), ex.getMessage());
        if (!ex.getErrors().isEmpty()) {
            problem.setProperty(ProblemDetails.ERRORS, ex.getErrors());
        }
        return handleExceptionInternal(ex, problem, new HttpHeaders(), ex.getStatus(), request);
    }

    /** Method validation on a class annotated {@code @Validated}. */
    @ExceptionHandler(ConstraintViolationException.class)
    ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException ex, WebRequest request) {
        List<FieldViolation> errors = ex.getConstraintViolations().stream()
                .map(v -> new FieldViolation(lastNode(v.getPropertyPath()), v.getMessage()))
                .toList();
        return handleExceptionInternal(ex, ProblemDetails.validation(errors), new HttpHeaders(),
                HttpStatus.BAD_REQUEST, request);
    }

    /** Everything else: 500, generic body, full details in the server log only. */
    @ExceptionHandler(Exception.class)
    ResponseEntity<Object> handleUnexpected(Exception ex, WebRequest request) {
        ProblemDetail problem = ProblemDetails.of(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR,
                ProblemDetails.INTERNAL_DETAIL);
        return handleExceptionInternal(ex, problem, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    // ---- Spring MVC exceptions rewritten into our codes -----------------------------

    /** {@code @Valid @RequestBody} (and {@code @Valid} model attributes / parameter objects). */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return handleExceptionInternal(ex, ProblemDetails.validation(violations(ex.getBindingResult())),
                headers, HttpStatus.BAD_REQUEST, request);
    }

    /** Constraints on {@code @RequestParam}, {@code @PathVariable}, ... (Spring's built-in method validation). */
    @Override
    protected ResponseEntity<Object> handleHandlerMethodValidationException(HandlerMethodValidationException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldViolation> errors = new ArrayList<>();
        for (ParameterValidationResult result : ex.getParameterValidationResults()) {
            if (result instanceof ParameterErrors bean) {
                bean.getFieldErrors().forEach(fe -> errors.add(violation(fe)));
                bean.getGlobalErrors().forEach(ge -> errors.add(new FieldViolation(bean.getObjectName(), message(ge))));
            } else {
                String name = result.getMethodParameter().getParameterName();
                for (MessageSourceResolvable error : result.getResolvableErrors()) {
                    errors.add(new FieldViolation(name, message(error)));
                }
            }
        }
        if (!status.is4xxClientError()) {
            // Return-value validation failed: our bug, not the caller's.
            return handleExceptionInternal(ex, null, headers, status, request);
        }
        return handleExceptionInternal(ex, ProblemDetails.validation(errors), headers, HttpStatus.BAD_REQUEST,
                request);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {
        String field = ex.getPropertyName() != null ? ex.getPropertyName() : "request";
        String expected = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "value";
        List<FieldViolation> errors = List.of(new FieldViolation(field, "must be a valid " + expected));
        return handleExceptionInternal(ex, ProblemDetails.validation(errors), headers, HttpStatus.BAD_REQUEST,
                request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldViolation> errors = List.of(new FieldViolation(ex.getParameterName(), "is required"));
        return handleExceptionInternal(ex, ProblemDetails.validation(errors), headers, HttpStatus.BAD_REQUEST,
                request);
    }

    /** Broken JSON, wrong JSON shape, or no body. Jackson's message is not echoed (it quotes the input). */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail problem = ProblemDetails.of(HttpStatus.BAD_REQUEST, ErrorCode.MALFORMED_JSON,
                "The request body is missing or is not valid JSON.");
        return handleExceptionInternal(ex, problem, headers, HttpStatus.BAD_REQUEST, request);
    }

    /** Unknown route. Spring 7 raises this one (static-resource fallback), not NoHandlerFoundException. */
    @Override
    protected ResponseEntity<Object> handleNoResourceFoundException(NoResourceFoundException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail problem = ProblemDetails.of(HttpStatus.NOT_FOUND, ErrorCode.NOT_FOUND,
                ProblemDetails.NOT_FOUND_DETAIL);
        return handleExceptionInternal(ex, problem, headers, HttpStatus.NOT_FOUND, request);
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        ProblemDetail problem = ProblemDetails.of(HttpStatus.NOT_FOUND, ErrorCode.NOT_FOUND,
                ProblemDetails.NOT_FOUND_DETAIL);
        return handleExceptionInternal(ex, problem, headers, HttpStatus.NOT_FOUND, request);
    }

    // ---- the single exit point ------------------------------------------------

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
            HttpStatusCode statusCode, WebRequest request) {
        ProblemDetail problem = body instanceof ProblemDetail pd ? pd
                : ProblemDetail.forStatusAndDetail(statusCode, defaultDetail(ex, statusCode));
        String requestId = requestId(request);
        if (statusCode.is5xxServerError()) {
            log.error("Request failed with {} (requestId={})", statusCode.value(), requestId, ex);
        } else {
            log.debug("Request rejected with {}: {} (requestId={})", statusCode.value(),
                    ex.getClass().getSimpleName(), requestId);
        }
        if (request instanceof NativeWebRequest nwr) {
            HttpServletResponse response = nwr.getNativeResponse(HttpServletResponse.class);
            if (response != null && response.isCommitted()) {
                return null; // too late to send a body; the failure is logged above
            }
        }
        ProblemDetails.complete(problem, requestId);
        HttpHeaders out = new HttpHeaders();
        out.putAll(headers);
        out.setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        return ResponseEntity.status(statusCode).headers(out).body(problem);
    }

    // ---- helpers ------------------------------------------------------------------

    private static String defaultDetail(Exception ex, HttpStatusCode status) {
        if (status.is5xxServerError()) {
            return ProblemDetails.INTERNAL_DETAIL;
        }
        // Spring's own ErrorResponse details (405, 415, ...) are fixed texts without user input.
        if (ex instanceof org.springframework.web.ErrorResponse er && er.getBody().getDetail() != null) {
            return er.getBody().getDetail();
        }
        HttpStatus known = HttpStatus.resolve(status.value());
        return known != null ? known.getReasonPhrase() : "Request failed";
    }

    private static String requestId(WebRequest request) {
        if (request instanceof NativeWebRequest nwr) {
            HttpServletRequest servlet = nwr.getNativeRequest(HttpServletRequest.class);
            if (servlet != null) {
                return RequestIdFilter.get(servlet);
            }
        }
        return null;
    }

    private static List<FieldViolation> violations(BindingResult result) {
        List<FieldViolation> errors = new ArrayList<>();
        result.getFieldErrors().forEach(fe -> errors.add(violation(fe)));
        for (ObjectError ge : result.getGlobalErrors()) {
            errors.add(new FieldViolation(ge.getObjectName(), message(ge)));
        }
        return errors;
    }

    private static FieldViolation violation(FieldError fe) {
        // A binding failure's default message quotes the rejected value: replace it.
        String message = fe.isBindingFailure() ? "has an invalid value" : message(fe);
        return new FieldViolation(fe.getField(), message);
    }

    private static String message(MessageSourceResolvable error) {
        return error.getDefaultMessage() != null ? error.getDefaultMessage() : "is invalid";
    }

    private static String lastNode(Path path) {
        String name = null;
        for (Path.Node node : path) {
            name = node.getName();
        }
        return name != null ? name : path.toString();
    }
}

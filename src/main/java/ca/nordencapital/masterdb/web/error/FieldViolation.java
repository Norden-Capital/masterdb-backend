package ca.nordencapital.masterdb.web.error;

/**
 * One entry of the {@code errors} array on a {@code VALIDATION_FAILED} response.
 * The rejected value is never echoed back.
 *
 * @param field   body field ({@code email}, {@code address.city}) or query parameter ({@code size})
 * @param message what is wrong with it, for people
 */
public record FieldViolation(String field, String message) {
}

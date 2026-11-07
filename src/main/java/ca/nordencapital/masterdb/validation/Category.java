package ca.nordencapital.masterdb.validation;

/**
 * The six results of a validation, with the user's meanings (spec, addition 1).
 * Stored by name: add new ones, never rename.
 */
public enum Category {
    /** The provider accepted the address and refused two made-up ones at the same domain. */
    VALID,
    /** The mailbox doesn't exist (or the domain accepts no mail at all). */
    BOUNCE,
    /** The mailbox exists but is full. */
    SOFT_BOUNCE,
    /** An explicit policy refusal from the email provider. */
    REJECT,
    /** The domain accepts every address, so this one can't be proven. */
    CATCH_ALL,
    /** Not proven either way. Can always be retried; never counted as a bounce. */
    UNKNOWN
}

package ca.nordencapital.masterdb.auth.user;

/** Stored as text; the values must match chk_users_status in V1__users.sql. */
public enum UserStatus {
    /** Can sign in. Always has a password. */
    ACTIVE,
    /** Invited, has not set a password yet. Cannot sign in. */
    INVITED,
    /** Switched off by the Owner. Cannot sign in. Never the Owner. */
    DISABLED
}

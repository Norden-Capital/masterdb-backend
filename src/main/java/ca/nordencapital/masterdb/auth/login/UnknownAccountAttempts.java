package ca.nordencapital.masterdb.auth.login;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Failure counts for emails that have no account, kept in memory.
 *
 * <p>Without this, the lockout itself would reveal which emails exist: five
 * wrong passwords on a real account answer "locked", on a made-up one they
 * would go on answering "wrong credentials" forever. So made-up emails are
 * counted and "locked" exactly like real ones, only not in the database.
 *
 * <p>Bounded: entries are forgotten a day after their last failure, and the
 * map never holds more than {@link #MAX_ENTRIES} (the per-address rate limit
 * keeps it far below that in practice). A restart forgets everything here,
 * which only gives a made-up email a fresh count.
 */
final class UnknownAccountAttempts {

    static final int MAX_ENTRIES = 10_000;
    static final Duration FORGET_AFTER = Duration.ofDays(1);

    private record State(int failures, Instant lastFailure, Instant lockedUntil) {
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private final int maxAttempts;
    private final Duration lockDuration;

    UnknownAccountAttempts(int maxAttempts, Duration lockDuration) {
        this.maxAttempts = maxAttempts;
        this.lockDuration = lockDuration;
    }

    /** The end of a lock still running at {@code now}, or null. An expired lock starts a fresh count. */
    Instant lockedUntil(String email, Instant now) {
        State state = states.get(email);
        if (state == null || state.lockedUntil() == null) {
            return null;
        }
        if (now.isBefore(state.lockedUntil())) {
            return state.lockedUntil();
        }
        states.remove(email, state);
        return null;
    }

    /** Counts one failure. Returns the lock's end when this failure locks the email, otherwise null. */
    Instant recordFailure(String email, Instant now) {
        if (states.size() >= MAX_ENTRIES && !states.containsKey(email)) {
            prune(now);
        }
        State next = states.compute(email, (key, current) -> {
            int failures = (current == null ? 0 : current.failures()) + 1;
            Instant lockedUntil = failures >= maxAttempts ? now.plus(lockDuration) : null;
            return new State(failures, now, lockedUntil);
        });
        return next.lockedUntil();
    }

    void clear() {
        states.clear();
    }

    private void prune(Instant now) {
        states.entrySet().removeIf(e -> {
            State s = e.getValue();
            boolean lockOver = s.lockedUntil() == null || !now.isBefore(s.lockedUntil());
            return lockOver && !now.isBefore(s.lastFailure().plus(FORGET_AFTER));
        });
        if (states.size() >= MAX_ENTRIES) {
            // Still full: someone is spraying made-up emails from many addresses.
            // Starting over is safe; it only resets counts for emails nobody owns.
            states.clear();
        }
    }
}

package ca.nordencapital.masterdb.servers.ssh;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/** SSH public keys as text: the OpenSSH line ("ssh-ed25519 AAAA...") and the SHA256 fingerprint. */
public final class SshKeys {

    private SshKeys() {
    }

    /** "ssh-ed25519 AAAA..." without a comment. */
    public static String openSsh(PublicKey key) {
        return PublicKeyEntry.toString(key);
    }

    /** "SHA256:..." as ssh-keygen -lf prints it. */
    public static String fingerprint(PublicKey key) {
        return KeyUtils.getFingerPrint(key);
    }

    public static String type(PublicKey key) {
        return KeyUtils.getKeyType(key);
    }

    public static PublicKey parse(String openSsh) {
        try {
            return PublicKeyEntry.parsePublicKeyEntry(openSsh.trim()).resolvePublicKey(null, null, null);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("stored SSH public key is unreadable", e);
        }
    }

    /** Exactly the same key (type and bytes), not just the same fingerprint text. */
    public static boolean same(PublicKey presented, String pinnedOpenSsh) {
        return pinnedOpenSsh != null && KeyUtils.compareKeys(presented, parse(pinnedOpenSsh));
    }
}

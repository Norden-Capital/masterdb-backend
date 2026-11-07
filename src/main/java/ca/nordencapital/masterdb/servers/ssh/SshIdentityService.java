package ca.nordencapital.masterdb.servers.ssh;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

/**
 * MasterDB's one SSH key pair (ed25519), made the first time it is needed.
 * The private key is stored encrypted with ENCRYPTION_KEY and only ever
 * decrypted in memory to log in to a server: it is never returned by the API
 * and never logged. Only the public key and its fingerprint are shown.
 */
@Service
public class SshIdentityService {

    static final String CONTEXT = "ssh:identity";
    static final String COMMENT = "masterdb";
    private static final Logger log = LoggerFactory.getLogger(SshIdentityService.class);

    private final JdbcTemplate jdbc;
    private final SecretCipher cipher;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;

    public SshIdentityService(JdbcTemplate jdbc, SecretCipher cipher, ActivityLog activity, Clock clock,
            PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.cipher = cipher;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    /** What the user copies to the VPS. */
    public record PublicIdentity(String publicKey, String fingerprint, String installCommand, Instant createdAt) {
    }

    public PublicIdentity publicIdentity() {
        ensure();
        return jdbc.queryForObject("select public_key, fingerprint, created_at from ssh_identity where id = 1",
                (rs, n) -> new PublicIdentity(rs.getString(1), rs.getString(2), installCommand(rs.getString(1)),
                        rs.getTimestamp(3).toInstant()));
    }

    /** Package-private on purpose: only the SSH client in this package uses the private key. */
    KeyPair keyPair() {
        ensure();
        String enc = jdbc.queryForObject("select private_key_enc from ssh_identity where id = 1", String.class);
        byte[] pem = cipher.decrypt(enc, CONTEXT);
        try {
            return SecurityUtils.loadKeyPairIdentities(null, () -> "masterdb-ssh-key", new ByteArrayInputStream(pem),
                    null).iterator().next();
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("MasterDB's SSH key can't be read (was ENCRYPTION_KEY changed?)");
        } finally {
            Arrays.fill(pem, (byte) 0);
        }
    }

    /**
     * A one-line command for the VPS: adds the key to the login user's
     * authorized_keys once (running it again changes nothing).
     */
    static String installCommand(String publicKey) {
        return "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 "
                + "~/.ssh/authorized_keys && (grep -qxF '" + publicKey + "' ~/.ssh/authorized_keys || echo '"
                + publicKey + "' >> ~/.ssh/authorized_keys)";
    }

    private void ensure() {
        Integer count = jdbc.queryForObject("select count(*) from ssh_identity", Integer.class);
        if (count != null && count > 0) {
            return;
        }
        KeyPair pair;
        byte[] pem;
        try {
            pair = KeyUtils.generateKeyPair("ssh-ed25519", 256);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(pair, COMMENT, null, out);
            pem = out.toByteArray();
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("couldn't generate the SSH key pair", e);
        }
        String publicKey = SshKeys.openSsh(pair.getPublic()) + " " + COMMENT;
        String fingerprint = SshKeys.fingerprint(pair.getPublic());
        String enc = cipher.encrypt(pem, CONTEXT);
        Arrays.fill(pem, (byte) 0);
        Boolean created = tx.execute(status -> {
            int rows = jdbc.update("insert into ssh_identity (id, public_key, fingerprint, private_key_enc, "
                    + "created_at) values (1, ?, ?, ?, ?) on conflict (id) do nothing", publicKey, fingerprint, enc,
                    Timestamp.from(clock.instant()));
            if (rows == 1) {
                activity.record(ActivityAction.SSH_KEY_CREATED, Party.label("MasterDB"), Party.label("SSH key"),
                        Map.of("fingerprint", fingerprint, "type", "ssh-ed25519"));
            }
            return rows == 1;
        });
        if (Boolean.TRUE.equals(created)) {
            log.info("ssh key pair created: {} (private key stored encrypted, never shown)", fingerprint);
        }
    }
}

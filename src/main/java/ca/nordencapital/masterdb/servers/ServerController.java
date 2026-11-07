package ca.nordencapital.masterdb.servers;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.servers.ServerService.ConnectResult;
import ca.nordencapital.masterdb.servers.ServerService.ConnectionStatus;
import ca.nordencapital.masterdb.servers.ServerService.Expiry;
import ca.nordencapital.masterdb.servers.ServerService.Filter;
import ca.nordencapital.masterdb.servers.ServerService.HealthFilter;
import ca.nordencapital.masterdb.servers.ServerService.Input;
import ca.nordencapital.masterdb.servers.ServerService.ServerItem;
import ca.nordencapital.masterdb.servers.ssh.SshIdentityService;
import ca.nordencapital.masterdb.servers.ssh.SshIdentityService.PublicIdentity;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.UUID;

/** VPS servers (Server management job 1). */
@Tag(name = "Servers")
@RestController
@RequestMapping("/api/v1/servers")
public class ServerController {

    private final ServerService service;
    private final SshIdentityService identity;

    public ServerController(ServerService service, SshIdentityService identity) {
        this.service = service;
        this.identity = identity;
    }

    public record ServerRequest(@Size(max = 200) String name, @Size(max = 100) String ip, Integer sshPort,
            @Size(max = 100) String sshUser, LocalDate expiresOn, @Size(max = 4000) String notes, UUID domainId) {
        Input input() {
            return new Input(name, ip, sshPort, sshUser, expiresOn, notes, domainId);
        }
    }

    public record FingerprintRequest(@NotBlank @Size(max = 100) String fingerprint) {
    }

    /** Trust, optionally with the login user's password (used once to add MasterDB's key, never stored). */
    public record TrustRequest(@NotBlank @Size(max = 100) String fingerprint, @Size(max = 1024) String password) {
        @Override
        public String toString() {
            return "TrustRequest[fingerprint=" + fingerprint + "]";
        }
    }

    public record PasswordRequest(@NotBlank @Size(max = 1024) String password) {
        @Override
        public String toString() {
            return "PasswordRequest[hidden]";
        }
    }

    public record IdentityRequest(@Size(max = 300) String heloHost, @Size(max = 300) String mailFrom) {
    }

    @Operation(summary = "Set the probe identity", description = "HELO host and MAIL FROM that Validation will "
            + "use from this server; both on the linked domain (the domain or a subdomain). Linking a domain sets "
            + "them to mail.<domain> and postmaster@<domain>. 409 SERVER_NOT_READY without a linked domain.")
    @RequiresPermission(module = Module.SERVERS, action = Action.EDIT)
    @PutMapping("/{id}/identity")
    public ServerItem identity(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody IdentityRequest body) {
        return service.identity(caller, id, body.heloHost(), body.mailFrom());
    }

    @Operation(summary = "MasterDB's SSH public key", description = "The one ed25519 key MasterDB logs in with "
            + "(made on first call), its fingerprint and a one-line command that adds it to authorized_keys on a "
            + "VPS. The private key is never returned.")
    @RequiresPermission(module = Module.SERVERS, action = Action.VIEW)
    @GetMapping("/ssh-key")
    public PublicIdentity sshKey() {
        return identity.publicIdentity();
    }

    @Operation(summary = "List servers", description = "Search `q` in name and IP; filter `connection` "
            + "(NEW, KEY_PENDING, CONNECTED, AUTH_FAILED, UNREACHABLE, KEY_CHANGED), `expiry` (EXPIRED, DAYS_14, "
            + "DAYS_30), `health` (OK, WARNING, PROBLEM, ERROR, UNCHECKED). Sort: name, ip, expiresOn, createdAt, "
            + "connectionStatus, healthStatus.")
    @RequiresPermission(module = Module.SERVERS, action = Action.VIEW)
    @GetMapping
    public PageResponse<ServerItem> list(@ParameterObject PageParams params,
            @RequestParam(required = false) String q, @RequestParam(required = false) ConnectionStatus connection,
            @RequestParam(required = false) Expiry expiry, @RequestParam(required = false) HealthFilter health) {
        return service.list(new Filter(q, connection, expiry, health),
                params.toPageable(ServerService.SORT_COLUMNS.keySet(), Sort.by("name")));
    }

    @RequiresPermission(module = Module.SERVERS, action = Action.VIEW)
    @GetMapping("/{id}")
    public ServerItem get(@PathVariable UUID id) {
        return service.find(id).item();
    }

    @Operation(summary = "Add a server", description = "Name, public IPv4, SSH port (22), SSH user (root), "
            + "expiry date, notes, optional linked domain. No password: MasterDB logs in with its own key.")
    @RequiresPermission(module = Module.SERVERS, action = Action.CREATE)
    @PostMapping
    public ResponseEntity<ServerItem> create(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody ServerRequest body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(caller, body.input()));
    }

    @Operation(summary = "Change a server", description = "A new IP or SSH port forgets the trusted host key "
            + "(it may be another machine): connect again.")
    @RequiresPermission(module = Module.SERVERS, action = Action.EDIT)
    @PutMapping("/{id}")
    public ServerItem update(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody ServerRequest body) {
        return service.update(caller, id, body.input());
    }

    @Operation(summary = "Delete a server", description = "Removes it from MasterDB only; nothing changes on the VPS.")
    @RequiresPermission(module = Module.SERVERS, action = Action.DELETE)
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        service.delete(caller, id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Connect", description = "Reads the host key. None trusted yet: `outcome` KEY_PENDING "
            + "with the fingerprint to check. The trusted one: logs in with MasterDB's key (CONNECTED, AUTH_FAILED "
            + "or UNREACHABLE). Another one: KEY_CHANGED, the server is blocked. Always 200; the server comes back "
            + "with its new state.")
    @RequiresPermission(module = Module.SERVERS, action = Action.RUN)
    @PostMapping("/{id}/connect")
    public ConnectResult connect(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.connect(caller, id);
    }

    @Operation(summary = "Trust the host key (first use)", description = "Send the fingerprint that was shown. "
            + "Optional `password` of the SSH user: MasterDB then logs in once with it, only to add its own key "
            + "(never stored, never logged). 409 if a key is already trusted or the fingerprint differs.")
    @RequiresPermission(module = Module.SERVERS, action = Action.CREATE)
    @PostMapping("/{id}/host-key/trust")
    public ConnectResult trust(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody TrustRequest body) {
        return service.trust(caller, id, body.fingerprint(), body.password());
    }

    @Operation(summary = "Add MasterDB's key with the password", description = "For a server whose host key is "
            + "trusted but that refuses MasterDB's key: logs in once with the SSH user's password, adds the key to "
            + "authorized_keys, then tests the key login. The password is never stored or logged.")
    @RequiresPermission(module = Module.SERVERS, action = Action.CREATE)
    @PostMapping("/{id}/install-key")
    public ConnectResult installKey(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody PasswordRequest body) {
        return service.installKey(caller, id, body.password());
    }

    @Operation(summary = "Accept a changed host key (Owner only)", description = "Only while the server is "
            + "blocked by a changed key; send the new fingerprint that was shown.")
    @RequiresPermission(module = Module.SERVERS, action = Action.EDIT)
    @PostMapping("/{id}/host-key/replace")
    public ConnectResult replace(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Validated @RequestBody FingerprintRequest body) {
        return service.replaceKey(caller, id, body.fingerprint());
    }
}

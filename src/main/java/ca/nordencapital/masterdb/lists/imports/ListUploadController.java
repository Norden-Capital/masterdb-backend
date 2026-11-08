package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.lists.ListRow.Source;
import ca.nordencapital.masterdb.lists.ListService.ListView;
import ca.nordencapital.masterdb.lists.imports.ListUploadService.CreateRequest;
import ca.nordencapital.masterdb.lists.imports.ListUploadService.Preview;
import ca.nordencapital.masterdb.lists.imports.ListUploadService.UploadState;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.UUID;

/** Add list: the details, the file in chunks (or a Drive link), the column choice, the import. */
@Tag(name = "Lists")
@RestController
@RequestMapping("/api/v1/lists")
public class ListUploadController {

    private final ListUploadService uploads;

    public ListUploadController(ListUploadService uploads) {
        this.uploads = uploads;
    }

    public record CreateBody(@Size(max = 300) String name, @Size(max = 300) String esp,
            @Size(max = 300) String country, @Size(max = 300) String vertical, Boolean removeDuplicates,
            Integer splitBy, Source source, @Size(max = 300) String fileName, Long fileSize,
            @Size(max = 2000) String driveUrl) {
    }

    public record ImportBody(Integer emailColumn, Boolean hasHeader) {
    }

    @Operation(summary = "Add a list", description = "The old app's fields (name required; `removeDuplicates`; "
            + "`splitBy` 0 = no split). `source` FILE: `fileName` (.txt or .csv) and `fileSize` (at most 2 GB), then "
            + "send the file with PUT …/upload. `source` DRIVE: `driveUrl` (a drive.google.com or docs.google.com "
            + "link shared as \"Anyone with the link\"); the server downloads it. 201 with the list.")
    @RequiresPermission(module = Module.LISTS, action = Action.CREATE)
    @PostMapping
    public ResponseEntity<ListView> create(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody CreateBody body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(uploads.create(caller, new CreateRequest(body.name(),
                body.esp(), body.country(), body.vertical(), body.removeDuplicates(), body.splitBy(), body.source(),
                body.fileName(), body.fileSize(), body.driveUrl())));
    }

    @Operation(summary = "Where the upload stands", description = "`received` = bytes the server has written to "
            + "disk: go on from there after a break.")
    @RequiresPermission(module = Module.LISTS, action = Action.CREATE)
    @GetMapping("/{id}/upload")
    public UploadState state(@PathVariable UUID id) {
        return uploads.state(id);
    }

    @Operation(summary = "Send one chunk", description = "Body: the file's bytes from `offset` on "
            + "(application/octet-stream, at most 4 MB). A chunk the server already has changes nothing; one that "
            + "starts past `received` is 409 UPLOAD_OFFSET_MISMATCH with `received`. The answer is what the server "
            + "has on disk; at the end the list moves to MAPPING.")
    @RequiresPermission(module = Module.LISTS, action = Action.CREATE)
    @PutMapping("/{id}/upload")
    public UploadState chunk(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @RequestParam long offset, HttpServletRequest request) throws IOException {
        return uploads.chunk(caller, id, offset, request.getInputStream());
    }

    @Operation(summary = "Preview the columns", description = "The first rows and the server's guess: separator, "
            + "header or not, which column holds the email, and how many addresses each column has in these rows.")
    @RequiresPermission(module = Module.LISTS, action = Action.CREATE)
    @GetMapping("/{id}/preview")
    public Preview preview(@PathVariable UUID id) {
        return uploads.preview(id);
    }

    @Operation(summary = "Import", description = "`emailColumn` (0-based) and `hasHeader` (both optional: the guess "
            + "is used). The import runs in the background; poll the list for its progress and report.")
    @RequiresPermission(module = Module.LISTS, action = Action.CREATE)
    @PostMapping("/{id}/import")
    public ListView startImport(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @RequestBody(required = false) ImportBody body) {
        return uploads.startImport(caller, id, body == null ? null : body.emailColumn(),
                body == null ? null : body.hasHeader());
    }
}

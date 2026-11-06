package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Test-only endpoints guarded by permissions; pulled in with @Import. */
@RestController
@RequestMapping("/api/v1/test-probe")
public class PermissionProbeController {

    @RequiresPermission(module = Module.CONTACTS, action = Action.EXPORT)
    @GetMapping("/contacts-export")
    public String contactsExport() {
        return "exported";
    }

    @RequiresPermission(module = Module.BACKUPS, action = Action.RUN)
    @GetMapping("/backups-run")
    public String backupsRun() {
        return "ran";
    }
}

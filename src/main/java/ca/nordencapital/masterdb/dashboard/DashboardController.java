package ca.nordencapital.masterdb.dashboard;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Numbers for the start page. */
@Tag(name = "Dashboard")
@RestController
@RequestMapping("/api/v1/dashboard")
public class DashboardController {

    private final DashboardService dashboard;

    public DashboardController(DashboardService dashboard) {
        this.dashboard = dashboard;
    }

    @Operation(summary = "Start page counts", description = "Only numbers MasterDB really has today: users by "
            + "status, open sessions, activity log entries in the last 24 hours and 7 days. Counted from the "
            + "database at the moment of the call.")
    @RequiresPermission(module = Module.DASHBOARD, action = Action.VIEW)
    @GetMapping("/summary")
    public DashboardService.Summary summary() {
        return dashboard.summary();
    }
}

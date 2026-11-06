package ca.nordencapital.masterdb.auth.permission;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

/** What can be granted, for the permissions editor. Any signed-in user may read it. */
@Tag(name = "Permissions")
@RestController
@RequestMapping("/api/v1/permissions")
public class PermissionController {

    public record ActionInfo(String key, String label) {
    }

    public record ModuleInfo(String key, String label, List<ActionInfo> actions) {
    }

    public record TemplateInfo(String key, String label, String description, List<String> permissions) {
    }

    public record Catalogue(List<ModuleInfo> modules, List<ActionInfo> actions, List<TemplateInfo> templates) {
    }

    @Operation(summary = "Permission catalogue", description = "Modules with their actions, all actions, and the "
            + "presets (templates) the editor offers. A permission is written MODULE:ACTION.")
    @GetMapping("/catalogue")
    public Catalogue catalogue() {
        List<ModuleInfo> modules = Arrays.stream(Module.values())
                .map(m -> new ModuleInfo(m.name(), m.label(),
                        m.actions().stream().map(a -> new ActionInfo(a.name(), a.label())).toList()))
                .toList();
        List<ActionInfo> actions = Arrays.stream(Action.values())
                .map(a -> new ActionInfo(a.name(), a.label())).toList();
        List<TemplateInfo> templates = PermissionTemplates.all().stream()
                .map(t -> new TemplateInfo(t.key(), t.label(), t.description(),
                        t.permissions().stream().map(Permission::toString).toList()))
                .toList();
        return new Catalogue(modules, actions, templates);
    }
}

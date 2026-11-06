package ca.nordencapital.masterdb.auth.permission;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionTest {

    @Test
    void parsesAndPrintsModuleColonAction() {
        Permission p = Permission.parse("CONTACTS:EXPORT");
        assertThat(p).isEqualTo(new Permission(Module.CONTACTS, Action.EXPORT));
        assertThat(p).hasToString("CONTACTS:EXPORT");
    }

    @Test
    void refusesUnknownNamesAndActionsAModuleDoesNotHave() {
        for (String bad : new String[] {"CONTACTS", "NOPE:VIEW", "CONTACTS:NOPE", "SETTINGS:DELETE",
                "ACTIVITY_LOG:EDIT", "contacts:view"}) {
            assertThatThrownBy(() -> Permission.parse(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void anyActionImpliesView() {
        assertThat(Permission.withImpliedView(Set.of(Permission.parse("CONTACTS:EXPORT"),
                Permission.parse("BACKUPS:RUN"))))
                .extracting(Permission::toString)
                .containsExactly("CONTACTS:VIEW", "CONTACTS:EXPORT", "BACKUPS:VIEW", "BACKUPS:RUN");
    }

    @Test
    void theOwnerHoldsEveryModulesActions() {
        int expected = 0;
        for (Module m : Module.values()) {
            expected += m.actions().size();
        }
        assertThat(Permission.all()).hasSize(expected);
    }

    @Test
    void templatesAreValidPresets() {
        assertThat(PermissionTemplates.all()).extracting(PermissionTemplates.Template::key)
                .containsExactly("VIEWER", "OPERATOR", "ADMIN");
        PermissionTemplates.all().forEach(t ->
                assertThat(Permission.withImpliedView(t.permissions())).isEqualTo(t.permissions()));
        PermissionTemplates.Template viewer = PermissionTemplates.all().getFirst();
        assertThat(viewer.permissions()).allMatch(p -> p.action() == Action.VIEW)
                .noneMatch(p -> p.module() == Module.USERS);
    }
}

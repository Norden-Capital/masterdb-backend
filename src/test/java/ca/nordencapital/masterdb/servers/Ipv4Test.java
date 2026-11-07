package ca.nordencapital.masterdb.servers;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4Test {

    @Test
    void formatAndPublicSpace() {
        assertThat(Ipv4.valid("147.93.4.107")).isTrue();
        assertThat(Ipv4.valid("256.1.1.1")).isFalse();
        assertThat(Ipv4.valid("01.2.3.4")).isFalse();
        assertThat(Ipv4.valid("1.2.3")).isFalse();
        assertThat(Ipv4.isPublic("147.93.4.107")).isTrue();
        for (String ip : new String[] {"10.0.0.1", "127.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.1.1",
                "100.64.0.1", "0.1.2.3", "224.0.0.1", "203.0.113.10", "198.51.100.1", "192.0.2.1"}) {
            assertThat(Ipv4.isPublic(ip)).as(ip).isFalse();
        }
        assertThat(Ipv4.reversed("1.2.3.4")).isEqualTo("4.3.2.1");
    }

    @Test
    void osReleaseIsRead() {
        ServerService.Os os = ServerService.Os.parse("""
                MASTERDB_LOGIN_TEST
                ID="almalinux"
                VERSION_ID="9.4"
                PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
                MASTERDB_UID=1001
                MASTERDB_SUDO=yes
                """);
        assertThat(os).isEqualTo(new ServerService.Os("almalinux", "9.4", "AlmaLinux 9.4 (Seafoam Ocelot)", true));
        assertThat(ServerService.Os.parse("MASTERDB_UID=1001\nMASTERDB_SUDO=no").privileged()).isFalse();
    }
}

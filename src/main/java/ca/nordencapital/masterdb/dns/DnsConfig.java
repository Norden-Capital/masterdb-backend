package ca.nordencapital.masterdb.dns;

import ca.nordencapital.masterdb.dns.namecheap.NamecheapProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** DNS management settings ({@code app.namecheap.*}). */
@Configuration
@EnableConfigurationProperties(NamecheapProperties.class)
public class DnsConfig {
}

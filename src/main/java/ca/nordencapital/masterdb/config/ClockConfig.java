package ca.nordencapital.masterdb.config;

import ca.nordencapital.masterdb.auth.AuthProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * The application's clock, in UTC. Code that decides by time (session expiry,
 * account lockout, rate limits) takes it instead of calling
 * {@code Instant.now()}, so tests can move time forward. A test overrides it
 * with a {@code @Primary} clock of its own.
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class ClockConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}

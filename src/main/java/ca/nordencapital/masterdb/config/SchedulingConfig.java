package ca.nordencapital.masterdb.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Turns on {@code @Scheduled} jobs (activity-log pruning). */
@Configuration
@EnableScheduling
public class SchedulingConfig {
}

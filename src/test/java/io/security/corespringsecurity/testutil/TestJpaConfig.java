package io.security.corespringsecurity.testutil;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@TestConfiguration
@EnableJpaRepositories(basePackages = {
        "io.security.corespringsecurity.repository",
        "io.security.corespringsecurity.service"
})
public class TestJpaConfig {
}

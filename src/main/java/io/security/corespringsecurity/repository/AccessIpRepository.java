package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.AccessIp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {
    Optional<AccessIp> findByIpAddress(String ipAddress);
}

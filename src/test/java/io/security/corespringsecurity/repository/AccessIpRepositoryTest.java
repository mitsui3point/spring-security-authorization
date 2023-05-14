package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.testutil.TestJpaConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Optional;

import static io.security.corespringsecurity.testutil.TestConfig.getAccessIp;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(SpringExtension.class)
@Import(TestJpaConfig.class)
@DataJpaTest
public class AccessIpRepositoryTest {
    @Autowired
    AccessIpRepository accessIpRepository;

    @Test
    @DisplayName("AccessIpRepositoryTest Type 은 JpaRepository<AccessIp, Long> 타입이다.")
    void instanceOf() {
        boolean actual = accessIpRepository instanceof JpaRepository;
        assertThat(actual).isTrue();
    }

    @Test
    @DisplayName("AccessIp 를 IpAddress 로 단건 조회 성공한다.")
    void findByIpAddress() {
        //given
        AccessIp accessIp = accessIpRepository.save(getAccessIp());
        //when
        AccessIp actualAccessIp = accessIpRepository.findByIpAddress(getAccessIp().getIpAddress()).orElseGet(() -> AccessIp.builder().build());
        //then
        assertThat(actualAccessIp).isEqualTo(accessIp);
    }

    @Test
    @DisplayName("AccessIp 를 IpAddress 로 단건 조회 실패한다.")
    void findByIpAddressDuplicate() {
        //given
        AccessIp accessIp = accessIpRepository.save(getAccessIp());
        AccessIp accessIpDuplication = accessIpRepository.save(getAccessIp());
        //then
        assertThatThrownBy(() -> {
            //when
            AccessIp actualAccessIp = accessIpRepository.findByIpAddress(getAccessIp().getIpAddress()).orElseGet(() -> AccessIp.builder().build());
        }).isInstanceOf(IncorrectResultSizeDataAccessException.class);
    }

    @Test
    @DisplayName("AccessIp 를 IpAddress 로 단건 조회 데이터가 없을 경우 Optional로 판별한다.")
    void findByIpAddressNull() {
        //when
        Optional<AccessIp> actualAccessIp = accessIpRepository.findByIpAddress(getAccessIp().getIpAddress());
        //then
        assertThat(actualAccessIp).isNotPresent();
    }
}

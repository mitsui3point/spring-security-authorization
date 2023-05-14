package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.testutil.TestJpaConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import static io.security.corespringsecurity.testutil.TestConfig.*;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@Import(TestJpaConfig.class)
@DataJpaTest
public class RoleHierarchyRepositoryTest {
    @Autowired
    RoleHierarchyRepository roleHierarchyRepository;

    @Test
    @DisplayName("RoleHierarchyRepository Type 은 JpaRepository<RoleHierarchy, Long> 타입이다.")
    void instanceOf() {
        boolean actual = roleHierarchyRepository instanceof JpaRepository;
        assertThat(actual).isTrue();
    }

    @Test
    @DisplayName("하위 권한 이름에 해당하는 권한 정보를 찾는다.")
    @Transactional
    void findByChildName() {
        //given
        RoleHierarchy roleUser = getRoleUserHierarchy(getRoleManagerHierarchy(getRoleAdminHierarchy(null)));
        roleHierarchyRepository.save(roleUser);

        //when
        RoleHierarchy actual = roleHierarchyRepository.findByChildName(roleUser.getChildName());
        //then
        assertThat(actual).isEqualTo(roleUser);
    }
}

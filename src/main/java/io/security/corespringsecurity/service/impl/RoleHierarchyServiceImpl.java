package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service(value = "roleHierarchyService")
@RequiredArgsConstructor
public class RoleHierarchyServiceImpl implements RoleHierarchyService {
    private final RoleHierarchyRepository roleHierarchyRepository;

    @Override
    @Transactional
    public String findAllHierarchy() {
        List<RoleHierarchy> roleHierarchies = roleHierarchyRepository.findAll();
        Iterator<RoleHierarchy> iterator = roleHierarchies.iterator();
        StringBuilder result = new StringBuilder();

        while (iterator.hasNext()) {
            RoleHierarchy roleHierarchy = iterator.next();
            if (roleHierarchy.getParentName() != null) {
                result.append(roleHierarchy.getParentName().getChildName());
                result.append(" > ");
                result.append(roleHierarchy.getChildName());
                result.append("\n");
            }
        }
        return result.toString();
    }
}

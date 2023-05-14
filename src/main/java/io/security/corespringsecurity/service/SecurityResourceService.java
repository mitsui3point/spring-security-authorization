package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class SecurityResourceService {

    private final ResourcesRepository resourcesRepository;
    private final AccessIpRepository accessIpRepository;

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap();
        resourcesRepository.findAllResources()
                .stream()
                .forEach(resource -> result.put(
                        new AntPathRequestMatcher(resource.getResourceName()),
                        resource.getRoleSet()
                                .stream()
                                .map(role -> new SecurityConfig(role.getRoleName()))
                                .collect(Collectors.toList()))
                );
        return result;
    }

    public List<String> getAcceptIpList() {
        return accessIpRepository.findAll()
                .stream()
                .map(o -> o.getIpAddress())
                .collect(Collectors.toList());
    }
}

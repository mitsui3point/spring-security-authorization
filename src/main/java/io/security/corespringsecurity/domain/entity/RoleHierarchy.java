package io.security.corespringsecurity.domain.entity;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "ROLE_HIERARCHY")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Data
@ToString(exclude = {"parentName", "roleHierarchies"})
public class RoleHierarchy implements Serializable {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "child_name")
    private String childName;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_name", referencedColumnName = "child_name")
    private RoleHierarchy parentName;

    @OneToMany(mappedBy = "parentName", cascade = CascadeType.ALL)
    private Set<RoleHierarchy> roleHierarchies = new HashSet<RoleHierarchy>();

//    @Builder
//    public RoleHierarchy(Long id, String childName, RoleHierarchy parentName) {
//        this.id = id;
//        this.childName = childName;
//        this.parentName = parentName;
//    }
}

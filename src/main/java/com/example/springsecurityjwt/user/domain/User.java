package com.example.springsecurityjwt.user.domain;

import com.example.springsecurityjwt.user.domain.enums.UserAuthority;
import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String uniqueId;

    private String password;

    private String name;

    @Enumerated(EnumType.STRING)
    private UserAuthority authority;
}

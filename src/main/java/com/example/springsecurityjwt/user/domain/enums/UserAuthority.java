package com.example.springsecurityjwt.user.domain.enums;

import lombok.Getter;

@Getter
public enum UserAuthority {
    USER("사용자"),
    ADMIN("관리자");

    private final String korean;

    UserAuthority(String korean) {
        this.korean = korean;
    }

    public static UserAuthority from(String korean) {
        for (UserAuthority userAuthority : UserAuthority.values()) {
            if (userAuthority.getKorean().equals(korean)) {
                return userAuthority;
            }
        }
        throw new IllegalArgumentException("유효하지 않은 사용자 권한입니다.");
    }
}

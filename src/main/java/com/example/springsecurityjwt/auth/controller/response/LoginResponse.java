package com.example.springsecurityjwt.auth.controller.response;

import com.example.springsecurityjwt.auth.dto.AuthDto;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class LoginResponse {
    private String token;

    public static LoginResponse from(AuthDto dto) {
        return LoginResponse.builder().token(dto.getToken()).build();
    }
}

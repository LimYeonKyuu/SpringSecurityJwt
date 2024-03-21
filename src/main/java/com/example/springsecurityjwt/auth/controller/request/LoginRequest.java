package com.example.springsecurityjwt.auth.controller.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class LoginRequest {
    private String uniqueId;
    private String password;
}

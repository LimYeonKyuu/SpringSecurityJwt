package com.example.springsecurityjwt.auth.controller;

import com.example.springsecurityjwt.auth.controller.request.LoginRequest;
import com.example.springsecurityjwt.auth.controller.response.LoginResponse;
import com.example.springsecurityjwt.auth.dto.AuthDto;
import com.example.springsecurityjwt.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/api/auth/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(LoginResponse.from(authService.login(AuthDto.from(request))));
    }
}

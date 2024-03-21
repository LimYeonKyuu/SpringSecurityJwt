package com.example.springsecurityjwt.auth.dto;

import com.example.springsecurityjwt.auth.controller.request.LoginRequest;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
public class AuthDto {
  private Long id;
  private String uniqueId;
  private String password;
  private String token;

  public static AuthDto from(LoginRequest request) {
    return AuthDto.builder()
        .uniqueId(request.getUniqueId())
        .password(request.getPassword())
        .build();
  }
}

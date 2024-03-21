package com.example.springsecurityjwt.auth.service;

import com.example.springsecurityjwt.auth.dto.AuthDto;
import com.example.springsecurityjwt.auth.util.JwtUtil;
import com.example.springsecurityjwt.user.domain.User;
import com.example.springsecurityjwt.user.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    @Value("${custom.jwt.secret}")
    private String SECRET_KEY;

    @Value("${custom.jwt.expire-time-ms}")
    private long EXPIRE_TIME_MS;

    public User getLoginUser(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("해당 사용자를 찾을 수 없습니다."));
    }

    public AuthDto login(AuthDto dto) {
        User user = userRepository.findByUniqueId(dto.getUniqueId()).orElseThrow(() -> new IllegalArgumentException("해당 사용자를 찾을 수 없습니다."));
        if (!user.getPassword().equals(dto.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }
        return AuthDto.builder()
                .token(JwtUtil.createToken(user.getId(), SECRET_KEY, EXPIRE_TIME_MS))
                .build();
    }
}

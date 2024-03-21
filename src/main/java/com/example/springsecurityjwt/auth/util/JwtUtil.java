package com.example.springsecurityjwt.auth.util;


import com.example.springsecurityjwt.auth.exception.WrongTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class JwtUtil {
  // JWT Token 발급
  public static String createToken(Long memberId, String secretKey, long expireTimeMs) {
    // Claim = Jwt Token중 payload에 들어갈 정보
    // Claim에 memberId 넣어 줌으로써 나중에 memberId를 꺼낼 수 있음
    Claims claims = Jwts.claims();
    claims.put("memberId", memberId);

    return Jwts.builder()
        .setClaims(claims)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs))
        .signWith(SignatureAlgorithm.HS256, secretKey)
        .compact();
  }

  // Claims에서 memberId 꺼내기
  public static Long getMemberId(String token, String secretKey) {
    return extractClaims(token, secretKey).get("memberId", Long.class);
  }

  // SecretKey를 사용해 Token Decoding
  private static Claims extractClaims(String token, String secretKey) {
    try {
      return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    } catch (ExpiredJwtException e) {
      throw new WrongTokenException("만료된 토큰입니다.");
    } catch (Exception e) {
      throw new WrongTokenException("잘못된 토큰입니다.");
    }
  }
}

package com.spring_greens.presentation.auth.security.provider;

import com.spring_greens.presentation.auth.config.JwtProperties;
import com.spring_greens.presentation.auth.dto.CustomUser;
import com.spring_greens.presentation.auth.dto.UserDTO;
import com.spring_greens.presentation.auth.entity.RefreshToken;
import com.spring_greens.presentation.global.exception.JwtException;
import com.spring_greens.presentation.auth.repository.RefreshTokenRepository;
import com.spring_greens.presentation.global.enums.JwtErrorCode;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.WeakKeyException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;


import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@RequiredArgsConstructor
@Component
public class JwtProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);
    private final JwtProperties jwtProperties;
    private final SecretKey secretKey;
    private final RefreshTokenRepository refreshTokenRepository;

    public final static String HEADER_AUTHORIZATION = "Authorization";
    public final static String TOKEN_PREFIX = "Bearer ";
    public static final String Access_TOKEN_NAME = "access_token";
    public static final String REFRESH_TOKEN_NAME = "refresh_token";

    @Autowired
    public JwtProvider(JwtProperties jwtProperties, RefreshTokenRepository refreshTokenRepository) {
        this.jwtProperties = jwtProperties;
        // key는 직접 가져옴 ( 연산 최소화 )
        this.secretKey = jwtProperties.getSecretKey();
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public String generateAccessToken(CustomUser customUser) {
        Date now = new Date();
        return makeToken(new Date(now.getTime() + jwtProperties.getAccessTokenExpiration()), customUser);
    }
    // 테스트용
    public String generateAccessToken(CustomUser customUser, Duration expiredAt) {
        Date now = new Date();
        return makeToken(new Date(now.getTime() + expiredAt.toMillis()), customUser);
    }

    public String generateRefreshToken(CustomUser customUser) {
        Date now = new Date();
        String token = makeToken(new Date(now.getTime() + jwtProperties.getRefreshTokenExpiration()), customUser);

        RefreshToken refreshToken = new RefreshToken(customUser.getId(), token);

        logger.info(token);

        logger.info(customUser.getId()+"");

        // DB 저장
        refreshTokenRepository.insertOrUpdateRefreshToken(token, customUser.getId());

        return token;
    }
    // 테스트용
    public String generateRefreshToken(CustomUser customUser, Duration expiredAt) {
        Date now = new Date();
        String token = makeToken(new Date(now.getTime() + expiredAt.toMillis()), customUser);

        RefreshToken refreshToken = new RefreshToken(customUser.getId(), token);

        // DB 저장
        refreshTokenRepository.insertOrUpdateRefreshToken(token, customUser.getId());

        return token;
    }

    /* 버전 업에 따른 코드 변경
    Jws<Claims> jws = parser()
        .setSigningKey(jwtProperties.getSecretKey()) // 서명 키 설정
        .build() // 파서 빌드
        .parseClaimsJws(token); // JWT 파싱 및 검증

        // 클레임 본문 추출
    Claims claims = jws.getBody();
    */
    private String makeToken(Date expiry, CustomUser customUser) {
        Date now = new Date();

        return Jwts.builder()
                .issuer(jwtProperties.getIssuer())
                .issuedAt(now)
                .expiration(expiry)
                .subject(customUser.getEmail())
                .claim("id", customUser.getId())
                .claim("name", customUser.getName())
                .claim("role", customUser.getRole())
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }

    /* 검증을 각각 나눠서 진행 | 반환타입은 boolean에서 void로 변경*/
    public boolean validToken(String token) {
        /* java.lang.IllegalArgumentException: CharSequence cannot be null or empty. */
        if (token == null || token.trim().isEmpty()) {
            // 토큰이 없는 경우
            logger.info(JwtErrorCode.UNKNOWN_TOKEN.getMessage());
            return false;
//            throw new JwtNotValidateException(JwtErrorCode.UNKNOWN_TOKEN);
        }

        try {
            // JWT 파서 생성 및 설정
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey) // 서명 키 설정
                    .build()
                    .parseSignedClaims(token).getPayload(); // 파서 빌드

            /* 아래 null Check 부분은 굳이 필요한지 테스트 검증 해볼 것 */
/*
            // 유효성 검증: 서명 검증
            if (claims == null) {
                throw new JwtNotValidateException(JwtErrorCode.INVALID_CLAIMS_TOKEN);
            }

            // 유효성 검증: 만료일 확인
            Date expiration = claims.getExpiration();
            if (expiration == null) {
                throw new JwtNotValidateException(JwtErrorCode.INVALID_CLAIMS_TOKEN);
            }
*/
            // 만료 검증
            if (claims.getExpiration().before(new Date())) {
                logger.info(JwtErrorCode.EXPIRED_TOKEN.getMessage());
                throw new JwtException.JwtNotValidateException(JwtErrorCode.EXPIRED_TOKEN);
            }
            
            return true; // 토큰 정상
        } catch (SignatureException e) {
            logger.info(JwtErrorCode.WRONG_SIGNATURE_TOKEN.getMessage()+ " exception : " + e);
            throw new JwtException.JwtNotValidateException(JwtErrorCode.WRONG_SIGNATURE_TOKEN, e);
        } catch (MalformedJwtException e) {
            logger.info(JwtErrorCode.MALFORMED_TOKEN.getMessage()+ " exception : " + e);
            throw new JwtException.JwtNotValidateException(JwtErrorCode.MALFORMED_TOKEN, e);
        } catch (ExpiredJwtException e) {
            logger.info(JwtErrorCode.EXPIRED_TOKEN.getMessage()+ " exception : " + e);
            throw new JwtException.JwtNotValidateException(JwtErrorCode.EXPIRED_TOKEN, e);
        } catch (UnsupportedJwtException e) {
            logger.info(JwtErrorCode.UNSUPPORTED_TOKEN.getMessage()+ " exception : " + e);
            throw new JwtException.JwtNotValidateException(JwtErrorCode.UNSUPPORTED_TOKEN, e);
        } catch (IllegalArgumentException | DecodingException | WeakKeyException e) {
            logger.info(JwtErrorCode.INVALID_CLAIMS_TOKEN.getMessage()+ " exception : " + e);
            throw new JwtException.JwtNotValidateException(JwtErrorCode.INVALID_CLAIMS_TOKEN, e);
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey) // 서명 키 설정
                .build()
                .parseSignedClaims(token).getPayload();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        UserDTO userDTO = UserDTO.builder()
                .email(claims.getSubject())
                .id(claims.get("id", Long.class))
                .name(claims.get("name", String.class))
                .role(claims.get("role", String.class))
                .build();

        CustomUser customUser = new CustomUser(userDTO);

        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority(claims.get("role", String.class)));

        return new UsernamePasswordAuthenticationToken(customUser, token, authorities);
    }

    public CustomUser getCustomUser(String token) {
        Claims claims = getClaims(token);

        UserDTO userDTO = UserDTO.builder()
                .email(claims.getSubject())
                .id(claims.get("id", Long.class))
                .name(claims.get("name", String.class))
                .role(claims.get("role", String.class))
                .build();

        return new CustomUser(userDTO);
    }

    public RefreshToken getRefreshTokenFromDB(long userId) {
        return refreshTokenRepository.findByUserId(userId)
                .orElse(null);
    }
}
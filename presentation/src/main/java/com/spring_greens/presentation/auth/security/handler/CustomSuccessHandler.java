package com.spring_greens.presentation.auth.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring_greens.presentation.auth.dto.CustomUser;
import com.spring_greens.presentation.auth.security.provider.JwtProvider;
import com.spring_greens.presentation.auth.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomSuccessHandler.class);

    public static final String Access_TOKEN_NAME = "access_token";
    public static final String REFRESH_TOKEN_NAME = "refresh_token";
    public static final Duration COOKIE_DURATION = Duration.ofDays(1);
    public static final String REDIRECT_PATH = "/articles";

    @Autowired
    private final JwtProvider jwtProvider;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        logger.info("성공 핸들러부터 타네?");

        // OAuth2User, UserDetails 통합 구현체
        CustomUser customUser = (CustomUser) authentication.getPrincipal();



        // 토큰 생성 및 jwt 쿠키에 담아서 반환
        String accessToken = jwtProvider.generateAccessToken(customUser);
        String refreshToken = jwtProvider.generateRefreshToken(customUser); // 리프레시는 DB 저장

        // 쿠키에 리프레시 토큰 삭제 및 추가 | 만료기간은 리프레시 토큰의 유효기간
        addRefreshTokenToCookie(request, response, refreshToken);

        // ResponseBody에 엑세스 토큰 설정
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put(Access_TOKEN_NAME, accessToken);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);

        // ObjectMapper를 사용하여 Map을 JSON으로 변환
        objectMapper.writeValue(response.getWriter(), responseBody);

        /* 로그인 성공 후 리다이렉트를 할까 or 클라이언트한테 맡길까 */
        // clearAuthenticationAttributes(request, response); // 필요한 가 이거
        // String targetUrl = getTargetUrl(accessToken);
        // getRedirectStrategy().sendRedirect(request, response, "http://localhost:8080/");
    }

/*
    private void saveRefreshToken(Long userId, String newRefreshToken) {
        RefreshToken refreshToken = refreshTokenRepository.findByUserId(userId)
                .map(entity -> entity.update(newRefreshToken))
                .orElse(new RefreshToken(userId, newRefreshToken));

        refreshTokenRepository.save(refreshToken);
    }
*/

    private void addRefreshTokenToCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        int cookieMaxAge = (int) COOKIE_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN_NAME);
        CookieUtil.addCookie(response, REFRESH_TOKEN_NAME, refreshToken, cookieMaxAge);
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        //super.clearAuthenticationAttributes(request);
//        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_PATH)
                .queryParam("token", token)
                .build()
                .toUriString();
    }
}
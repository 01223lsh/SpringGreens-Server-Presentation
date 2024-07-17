package com.spring_greens.presentation.auth.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import me.hoon.springbootdeveloper.config.jwt.TokenProvider;
import me.hoon.springbootdeveloper.dto.oauth.CustomOAuth2User;
import me.hoon.springbootdeveloper.service.OAuth2Service;
import me.hoon.springbootdeveloper.util.CookieUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Duration;

@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(14);
    public static final Duration ACCESS_TOKEN_DURATION = Duration.ofDays(1);
    public static final String REDIRECT_PATH = "/articles";

    private final TokenProvider tokenProvider;
//  private final RefreshTokenRepository refreshTokenRepository;
//  private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;
    private final OAuth2Service oAuth2Service;


    /**
     * TokenProvider를 구현체로 jwt토큰 생성
     *
     *
     *
     * @throws IOException
     */
    public void onTokenSuccess() throws IOException { }


        @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        //OAuth2User
        CustomOAuth2User customOAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        // 종현씌가 토큰에 쓰는 거 .. 일단 스탑
        String username = customOAuth2User.getUsername();
        String email = customOAuth2User.getEmail();

        // 토큰 생성 및 jwt 쿠키에 담아서 반환
        onTokenSuccess();


//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//        String role = auth.getAuthority();
//
//        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
//        User user = oAuth2Service.findByEmail((String) oAuth2User.getAttributes().get("email"));

//        String refreshToken = tokenProvider.generateToken(user, REFRESH_TOKEN_DURATION);
//        saveRefreshToken(user.getId(), refreshToken);
//        addRefreshTokenToCookie(request, response, refreshToken);

//        String accessToken = tokenProvider.generateToken(user, ACCESS_TOKEN_DURATION);
//        String targetUrl = getTargetUrl(accessToken);

        clearAuthenticationAttributes(request, response);

        //getRedirectStrategy().sendRedirect(request, response, "http://localhost:8080/login");
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
        int cookieMaxAge = (int) REFRESH_TOKEN_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN_COOKIE_NAME);
        CookieUtil.addCookie(response, REFRESH_TOKEN_COOKIE_NAME, refreshToken, cookieMaxAge);
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
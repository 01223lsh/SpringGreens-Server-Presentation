package com.spring_greens.presentation.auth.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring_greens.presentation.auth.dto.CustomUser;
import com.spring_greens.presentation.auth.entity.RefreshToken;
import com.spring_greens.presentation.auth.security.provider.JwtProvider;
import com.spring_greens.presentation.auth.util.CookieUtil;
import com.spring_greens.presentation.global.enums.JwtErrorCode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    /* BasicAuthenticationEntryPoint의 경우 HTTP Basic Authentication 방식 전용이며, jwt로 해당 방식을 대체하였기에 사용 x */
    /* 각 예외에 대한 결과코드만 뿌려줌, RefreshToken 같은 것들 때문에 case 문 추가할지도 */

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

    private final JwtProvider jwtProvider;

    private final ObjectMapper objectMapper;
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.info("Entry 잘 호출하네");
        JwtErrorCode jwtErrorCode = (JwtErrorCode) request.getAttribute("jwtErrorCode");

        // 코드상 에러 방지
        if (jwtErrorCode == null) {
            logger.info("여기서 걸리나?");
            /* authenticated() 로 인한 AuthenticationException이 발생하는 나머지 경우의 예외처리 추가 예정 */
            jwtErrorCode = JwtErrorCode.UNKNOWN_ERROR;
        }

        switch (jwtErrorCode) {
            case EXPIRED_TOKEN:
                logger.info("만료된 토큰입니다.");
                handleExpiredToken(request, response);
                break;
            default:
                logger.info("기타 에러입니다: " + jwtErrorCode);
                sendErrorResponse(response, jwtErrorCode);
                break;
        }
    }

    private void addRefreshTokenToCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        int cookieMaxAge = (int) CustomSuccessHandler.COOKIE_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, CustomSuccessHandler.REFRESH_TOKEN_NAME);
        CookieUtil.addCookie(response, CustomSuccessHandler.REFRESH_TOKEN_NAME, refreshToken, cookieMaxAge);
    }

    private void handleExpiredToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String requestRefreshToken = CookieUtil.getCookieValue(request, CustomSuccessHandler.REFRESH_TOKEN_NAME);
        if (requestRefreshToken == null) {
            sendErrorResponse(response, JwtErrorCode.MALFORMED_REFRESH_TOKEN);
            return;
        }

        if (!jwtProvider.validToken(requestRefreshToken)) {
            sendErrorResponse(response, JwtErrorCode.MALFORMED_REFRESH_TOKEN);
            return;
        }

        CustomUser customUser = jwtProvider.getCustomUser(requestRefreshToken);

//        for (GrantedAuthority authority : customUser.getAuthorities()) {
//            logger.info("사용자 '{}'의 권한: {}", customUser.getName(), authority.getAuthority());
//        }

        RefreshToken storedRefreshToken = jwtProvider.getRefreshTokenFromDB(customUser.getId());

        if (storedRefreshToken == null) {
            sendErrorResponse(response, JwtErrorCode.MALFORMED_REFRESH_TOKEN);
            return;
        }

        if (!storedRefreshToken.getRefreshToken().equals(requestRefreshToken)) {
            sendErrorResponse(response, JwtErrorCode.USED_REFRESH_TOKEN);
            return;
        }

        refreshTokensAndSendResponse(request, response, customUser);
    }

    private void refreshTokensAndSendResponse(HttpServletRequest request, HttpServletResponse response, CustomUser customUser) throws IOException {
        String accessToken = jwtProvider.generateAccessToken(customUser);
        String refreshToken = jwtProvider.generateRefreshToken(customUser);

        addRefreshTokenToCookie(request, response, refreshToken);

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put(CustomSuccessHandler.Access_TOKEN_NAME, accessToken);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);

        objectMapper.writeValue(response.getWriter(), responseBody);
    }

    private void sendErrorResponse(HttpServletResponse response, JwtErrorCode jwtErrorCode) throws IOException {
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("error", jwtErrorCode.getDescription());

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(jwtErrorCode.getHttpStatus().value());

        objectMapper.writeValue(response.getWriter(), responseBody);
    }
}

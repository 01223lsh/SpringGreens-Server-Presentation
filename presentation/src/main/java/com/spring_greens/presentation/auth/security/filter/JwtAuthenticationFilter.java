package com.spring_greens.presentation.auth.security.filter;

import com.spring_greens.presentation.global.exception.JwtException;
import com.spring_greens.presentation.auth.security.provider.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/* jwt 관련 인증과 인가로 필터를 나눌 수도 있음 | 추후 고려 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtProvider jwtProvider;
    @Override
    protected void doFilterInternal( HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(JwtProvider.HEADER_AUTHORIZATION);
        String token = getAccessToken(authorizationHeader);

        // 토큰 검증
        try {
            if(jwtProvider.validToken(token)) {
                logger.info("성공");
                Authentication authentication = jwtProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                logger.info("토큰 정상이야");
            }
        } catch (JwtException.JwtNotValidateException e) {
            logger.info("토큰 오류 잘 잡네");
            request.setAttribute("jwtErrorCode", e.getJwtErrorCode());
        }

        filterChain.doFilter(request, response);
    }
    private String getAccessToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(JwtProvider.TOKEN_PREFIX)) {
            return authorizationHeader.substring(JwtProvider.TOKEN_PREFIX.length());
        }
        return null;
    }
}
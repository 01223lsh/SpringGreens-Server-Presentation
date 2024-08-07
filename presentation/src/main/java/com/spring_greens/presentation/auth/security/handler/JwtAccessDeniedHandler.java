package com.spring_greens.presentation.auth.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        /** 403 권한 거부 에러를 뱉는다. | 권한 부족 관련 Exception Handler로 기능 추가 가능 */
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}

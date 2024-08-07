package com.spring_greens.presentation.auth.security.filter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/* 잡아서 넘겨도 되나, 각 필터에서 잡아도도 문제 없을 듯 */
public class JwtExceptionFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        try {
//            // Jwt 필터로 요청 전달
//            filterChain.doFilter(request, response);
//        } catch (JwtNotValidateException e) {
//            handleException(response, e);
//            ExceptionTranslationFilter
//        }
    }

//    private void handleException(HttpServletResponse response, JwtNotValidateException e) {
//        JwtErrorCode jwtErrorCode = e.getJwtErrorCode();
//
//        response.setStatus(jwtErrorCode.getHttpStatus().value());
//        response.setContentType("application/json; charset=UTF-8"); // 한글 인코딩 명시 | 필요 없을지도?
//
//        ErrorResponse errorResponse = new ErrorResponse(jwtErrorCode.getCode(), jwtErrorCode.getDescription());
//        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
//    }

}

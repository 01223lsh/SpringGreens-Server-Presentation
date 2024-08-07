package com.spring_greens.presentation.auth.exception;

import com.spring_greens.presentation.global.enums.JwtErrorCode;
import lombok.Getter;
import org.springframework.security.oauth2.jwt.JwtException;

@Getter
public class JwtNotValidateException extends JwtException {
    private final JwtErrorCode jwtErrorCode;
    public JwtNotValidateException(JwtErrorCode jwtErrorCode) {
        super(jwtErrorCode.getDescription());
        this.jwtErrorCode = jwtErrorCode;
    }

    public JwtNotValidateException(JwtErrorCode jwtErrorCode,Throwable cause) {
        super(jwtErrorCode.getDescription(), cause);
        this.jwtErrorCode = jwtErrorCode;
    }
}
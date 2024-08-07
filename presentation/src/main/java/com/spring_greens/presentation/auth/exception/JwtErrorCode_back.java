package com.spring_greens.presentation.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum JwtErrorCode_back {
    UNKNOWN_TOKEN(1001, "토큰이 존재하지 않습니다.", HttpStatus.BAD_REQUEST),
    WRONG_SIGNATURE_TOKEN(1002, "잘못된 JWT 서명입니다.", HttpStatus.BAD_REQUEST),
    MALFORMED_TOKEN(1003, "유효하지 않은 JWT 토큰입니다.", HttpStatus.BAD_REQUEST),
    EXPIRED_TOKEN(1004, "만료된 토큰입니다.", HttpStatus.UNAUTHORIZED),
    UNSUPPORTED_TOKEN(1005, "지원되지 않는 토큰입니다.", HttpStatus.BAD_REQUEST),
    INVALID_CLAIMS_TOKEN(1006, "JWT 토큰의 클레임이 잘못되었습니다.", HttpStatus.BAD_REQUEST),
    ACCESS_DENIED_TOKEN(1007, "권한이 없습니다.", HttpStatus.FORBIDDEN),
    UNKNOWN_ERROR(1111, "관리자에게 문의해주세요.", HttpStatus.UNAUTHORIZED);

    private final int code;
    private final String description;
    private final HttpStatus httpStatus;

    JwtErrorCode_back(int code, String description, HttpStatus httpStatus) {
        this.code = code;
        this.description = description;
        this.httpStatus = httpStatus;
    }
}
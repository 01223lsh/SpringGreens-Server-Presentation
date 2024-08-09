package com.spring_greens.presentation.global.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum JwtErrorCode {
    UNKNOWN_TOKEN("토큰이 존재하지 않습니다.", HttpStatus.BAD_REQUEST),
    WRONG_SIGNATURE_TOKEN( "잘못된 JWT 서명입니다.", HttpStatus.BAD_REQUEST),
    MALFORMED_TOKEN("유효하지 않은 JWT 토큰입니다.", HttpStatus.BAD_REQUEST),
    EXPIRED_TOKEN("만료된 토큰입니다. 새로운 토큰이 발급되었습니다.", HttpStatus.UNAUTHORIZED),
    UNSUPPORTED_TOKEN("지원되지 않는 토큰입니다.", HttpStatus.BAD_REQUEST),
    INVALID_CLAIMS_TOKEN("JWT 토큰의 클레임이 잘못되었습니다.", HttpStatus.BAD_REQUEST),
    ACCESS_DENIED_TOKEN("권한이 없습니다.", HttpStatus.FORBIDDEN),
    USED_REFRESH_TOKEN("만료된 엑세스 토큰입니다. 이미 사용된 리프레시 토큰입니다.", HttpStatus.BAD_REQUEST),
    MALFORMED_REFRESH_TOKEN("만료된 엑세스 토큰입니다. 리프레시 토큰이 유효하지 않습니다.", HttpStatus.BAD_REQUEST),
    UNKNOWN_ERROR( "알 수 없는 오류입니다. 관리자에게 문의해주세요.", HttpStatus.BAD_REQUEST);

    private final String message;
    private final HttpStatus httpStatus;

    JwtErrorCode(String message, HttpStatus httpStatus) {
        this.message = message;
        this.httpStatus = httpStatus;
    }
}

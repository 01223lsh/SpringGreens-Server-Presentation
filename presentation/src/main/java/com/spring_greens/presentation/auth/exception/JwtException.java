package com.spring_greens.presentation.auth.exception;

/*public abstract class JwtException extends RuntimeException {

    *//* Spring Oauth 패키지에서 이미 지원되나, 관련 Exception들을 모으기 위해 작성 -> 추후 Exception 별로 분리할수도*//*

    public JwtException(String message) {
        super(message);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }

    public static class JwtNotValidateException extends JwtException {
        private final JwtErrorCode jwtErrorCode;
        public JwtNotValidateException(JwtErrorCode jwtErrorCode, String message) {
            super(message);
            this.jwtErrorCode = jwtErrorCode;
        }

        public JwtNotValidateException(JwtErrorCode jwtErrorCode,String message,Throwable cause) {
            super(message, cause);
            this.jwtErrorCode = jwtErrorCode;
        }
    }
}*/







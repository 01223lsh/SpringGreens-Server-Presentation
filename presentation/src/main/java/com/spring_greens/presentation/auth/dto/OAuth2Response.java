package com.spring_greens.presentation.auth.dto;

public interface OAuth2Response {

    //써드파티 (Ex. naver, google, ...)
    String getProvider();
    //써드파티에서 발급해주는 아이디(번호)
    String getProviderId();
    //이메일
    String getEmail();
    //사용자 실명 (설정한 이름)
    String getName();
}
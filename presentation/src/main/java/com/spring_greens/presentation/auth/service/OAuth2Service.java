package com.spring_greens.presentation.auth.service;

import lombok.RequiredArgsConstructor;
import me.hoon.springbootdeveloper.dto.oauth.CustomOAuth2User;
import me.hoon.springbootdeveloper.dto.oauth.GoogleResponse;
import me.hoon.springbootdeveloper.dto.oauth.KakaoResponse;
import me.hoon.springbootdeveloper.dto.oauth.NaverResponse;
import me.hoon.springbootdeveloper.entity.User;
import me.hoon.springbootdeveloper.dto.*;
import me.hoon.springbootdeveloper.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;

@RequiredArgsConstructor
@Service
public class OAuth2Service extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User); // 로그로 변경 필요

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2ResponseEnum oAuth2ResponseEnum = OAuth2ResponseEnum.getByRegistrationId(registrationId);
        OAuth2Response oAuth2Response = null;
        if (oAuth2ResponseEnum != null) {
            oAuth2Response = oAuth2ResponseEnum.createResponse(oAuth2User.getAttributes());
        } else {
            throw new OAuth2AuthenticationException("Unsupported registrationId: " + registrationId);
        }

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬 -> 수정 예정
//        String username = oAuth2Response.getProvider()+" "+oAuth2Response.getProviderId();
        User existData = null;
        try{
            existData = this.findByEmail(oAuth2Response.getEmail());
        } catch (IllegalArgumentException e) {

        }
        // 존재하지 않으면 회원가입
        if (existData == null) {
            User user = new User();
            user.setEmail(oAuth2Response.getEmail());
            user.setName(oAuth2Response.getName());
            user.setRole("ROLE_SOCIAL");
            user.setSocialType(true);
            user.setSocialName(oAuth2Response.getProvider());

            userRepository.save(user);

            UserDTO userDTO = new UserDTO();
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("ROLE_SOCIAL");

            return new CustomOAuth2User(userDTO);
        }
        // 정보 업데이트
        else {
            
            // 같은 써드파티일 때만 사용자 이름 변경
            if(existData.getSocialName().equals(oAuth2Response.getProvider())) {

                // 엔티티 객체 값 변경
                existData.setEmail(oAuth2Response.getEmail());
                existData.setName(oAuth2Response.getName());

                // 실제 DB 변경
                userRepository.save(existData);
            }

            UserDTO userDTO = new UserDTO();
            userDTO.setId(existData.getId());
            userDTO.setName(existData.getName());
            userDTO.setRole(existData.getRole());

            return new CustomOAuth2User(userDTO);
        }
    }


    enum OAuth2ResponseEnum {
        NAVER {
            @Override
            public OAuth2Response createResponse(Map<String, Object> attributes) {
                return new NaverResponse(attributes);
            }
        },
        GOOGLE {
            @Override
            public OAuth2Response createResponse(Map<String, Object> attributes) {
                return new GoogleResponse(attributes);
            }
        },

        KAKAO {
            @Override
            public OAuth2Response createResponse(Map<String, Object> attributes) {
                return new KakaoResponse(attributes);
            }
        };

        public abstract OAuth2Response createResponse(Map<String, Object> attributes);

        public static OAuth2ResponseEnum getByRegistrationId(String registrationId) {
            for (OAuth2ResponseEnum provider : OAuth2ResponseEnum.values()) {
                if (provider.name().equalsIgnoreCase(registrationId)) {
                    return provider;
                }
            }
            return null;
        }
    }

/*
    private User saveOrUpdate(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        User user = userRepository.findByEmail(email)
                .map(entity -> entity.update(name))
                .orElse(User.builder()
                        .email(email)
                        .nickname(name)
                        .build());

        return userRepository.save(user);
    }

 */
    public User findByEmail(String email) {
       return userRepository.findByEmail(email)
               .orElseThrow(() -> new IllegalArgumentException("Unexpected user"));
    }


}
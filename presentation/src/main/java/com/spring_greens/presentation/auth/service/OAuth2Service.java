package com.spring_greens.presentation.auth.service;

import com.spring_greens.presentation.auth.dto.CustomUser;
import com.spring_greens.presentation.auth.dto.oauth.OAuth2Response;
import com.spring_greens.presentation.auth.dto.UserDTO;
import com.spring_greens.presentation.auth.dto.oauth.GoogleResponse;
import com.spring_greens.presentation.auth.dto.oauth.KakaoResponse;
import com.spring_greens.presentation.auth.dto.oauth.NaverResponse;
import com.spring_greens.presentation.auth.entity.User;
import com.spring_greens.presentation.auth.repository.UserRepository;
import com.spring_greens.presentation.auth.security.handler.CustomFailureHandler;
import com.spring_greens.presentation.global.enums.OAuth2ResponseEnum;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;

@RequiredArgsConstructor
@Service
public class OAuth2Service extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Service.class);

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        OAuth2Response oAuth2Response = createOAuth2Response(oAuth2User, userRequest.getClientRegistration().getRegistrationId());

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬 -> 수정 예정
//        String username = oAuth2Response.getProvider()+" "+oAuth2Response.getProviderId();

        User existData = findByEmail(oAuth2Response.getEmail());

        if (existData == null) {
            // 존재하지 않으면 회원가입
            return registerNewUser(oAuth2Response);
        } else {
            // 정보 업데이트
            updateExistingUser(existData, oAuth2Response);
            return createCustomUserDTO(existData);
        }
    }

    private OAuth2Response createOAuth2Response(OAuth2User oAuth2User, String registrationId) throws OAuth2AuthenticationException {
        OAuth2ResponseEnum oAuth2ResponseEnum = OAuth2ResponseEnum.getByRegistrationId(registrationId);
        if (oAuth2ResponseEnum == null) {
            throw new OAuth2AuthenticationException("지원되지 않는 공급자: " + registrationId);
        }
        return oAuth2ResponseEnum.createResponse(oAuth2User.getAttributes());
    }

    private CustomUser registerNewUser(OAuth2Response oAuth2Response) {
        User user = User.builder()
                .email(oAuth2Response.getEmail())
                .name(oAuth2Response.getName())
                .role("ROLE_SOCIAL")
                .socialType(true)
                .socialName(oAuth2Response.getProvider())
                .build();

        userRepository.save(user);

        UserDTO userDTO = UserDTO.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole())
                .build();

        return new CustomUser(userDTO);
    }

    private void updateExistingUser(User existingUser, OAuth2Response oAuth2Response) {
        // 같은 써드파티일 때만 사용자 이름 변경
        if (existingUser.getSocialName().equals(oAuth2Response.getProvider())) {

            // 엔티티 객체 값 변경
            existingUser.updateUserInfo(oAuth2Response.getEmail(), oAuth2Response.getName());

            // 실제 DB 변경
            userRepository.save(existingUser);
        }
    }

    private CustomUser createCustomUserDTO(User user) {
        UserDTO userDTO = UserDTO.builder()
                .id(user.getId())
                .name(user.getName())
                .role(user.getRole())
                .build();

        return new CustomUser(userDTO);
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
       return userRepository.findByEmail(email).orElse(null);
    }


}
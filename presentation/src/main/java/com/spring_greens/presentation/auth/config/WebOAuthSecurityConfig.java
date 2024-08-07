package com.spring_greens.presentation.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.impl.AAD;
import com.spring_greens.presentation.auth.security.handler.CustomFailureHandler;
import com.spring_greens.presentation.auth.security.handler.CustomSuccessHandler;
import com.spring_greens.presentation.auth.security.handler.JwtAccessDeniedHandler;
import com.spring_greens.presentation.auth.security.handler.JwtAuthenticationEntryPoint;
import com.spring_greens.presentation.auth.security.filter.JwtAuthenticationFilter;
import com.spring_greens.presentation.auth.security.provider.JwtProvider;
import com.spring_greens.presentation.auth.service.OAuth2Service;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@Configuration
public class WebOAuthSecurityConfig {

    private final OAuth2Service oAuth2Service;
    private final JwtProvider jwtProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final ObjectMapper objectMapper;

    @Bean
    public WebSecurityCustomizer configure() { // 스프링 시큐리티 기능 비활성화
        return (web) -> web.ignoring()
                .requestMatchers(
                        new AntPathRequestMatcher("/img/**"),
                        new AntPathRequestMatcher("/css/**"),
                        new AntPathRequestMatcher("/js/**")
                );
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable) // csrf disable
                .formLogin(AbstractHttpConfigurer::disable) // form 로그인 방식(default 방식) disable
                .httpBasic(AbstractHttpConfigurer::disable) // http basic 인증 방식 disable
                .logout(AbstractHttpConfigurer::disable)// logout disable
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth2/authorization/**", "/login", "/login/**", "/oauthLogin", "/", "/error","main").permitAll() // 허용된 URI
                        .anyRequest().authenticated() // 나머지 모든 요청은 인증 필요
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
//                      .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository()))
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userService(oAuth2Service))
                        .successHandler(customSuccessHandler())
                        .failureHandler(customFailureHandler())
                )
//                .exceptionHandling(exceptionHandling ->
//                         exceptionHandling
//                                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
//                                .accessDeniedHandler(jwtAccessDeniedHandler)
//                        )
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint(jwtAuthenticationEntryPoint())
                                .accessDeniedHandler(jwtAccessDeniedHandler)
                )
                .build();
    }

/*    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtProvider);
    }*/



    @Bean
    public CustomSuccessHandler customSuccessHandler() {
        return new CustomSuccessHandler(jwtProvider, objectMapper);
    }

    @Bean
    public CustomFailureHandler customFailureHandler() {
        return new CustomFailureHandler();
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint(jwtProvider, objectMapper);
    }

}
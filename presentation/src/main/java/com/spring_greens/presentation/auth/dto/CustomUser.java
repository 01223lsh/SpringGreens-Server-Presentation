package com.spring_greens.presentation.auth.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import lombok.Getter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class CustomUser implements UserDetails, OAuth2User {
    private final UserDTO userDTO;

    public CustomUser(UserDTO userDTO) { this.userDTO = userDTO; }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of(
                "id", userDTO.getId(),
                "name", userDTO.getName(),
                "email", userDTO.getEmail(),
                "role", userDTO.getRole()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ê¶Œí•œ ëª©ë¡ ?ƒ?„±
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(() -> userDTO.getRole().getRoleName());

        return authorities;
    }

    // ?¼ë°˜ê³¼ ?†µ?•©
    @Override
    public String getPassword() { return userDTO.getPassword(); }
    @Override
    public String getName() { return userDTO.getName(); }

    public String getUsername() {
        return userDTO.getName();
    }

    public Long getId() { return userDTO.getId(); }
    public String getEmail() {return userDTO.getEmail();}
   
    /*ê¶Œí•œ ?—¬?Ÿ¬ê°œë¡œ ë°”ë?Œë©´ ?ˆ˜? • ?•„?š”*/
    public String getRole() {
        return userDTO.getRole().getRoleName();
    }
    
    // ì¶”ê??? ?¸ ê²?ì¦? ?•„?š”
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
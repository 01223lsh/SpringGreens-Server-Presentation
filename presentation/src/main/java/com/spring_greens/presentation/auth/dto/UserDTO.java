package com.spring_greens.presentation.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    private long id;
    private String role;
    private String name;
    private String email;
}

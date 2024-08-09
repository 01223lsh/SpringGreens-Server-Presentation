package com.spring_greens.presentation.auth.dto;

import lombok.*;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@ToString
public class UserDTO {
    private long id;
    private String role;
    private String name;
    private String email;
}

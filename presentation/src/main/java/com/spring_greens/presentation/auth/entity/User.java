package com.spring_greens.presentation.auth.entity;

import jakarta.persistence.*;
import lombok.*;

@Table(name = "USER")
@Getter
@Setter
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role", nullable = false)
    private String role;

    @Column(name = "email", nullable = false, length = 100)
    private String email;

    @Column(name = "contact", length = 20)
    private String contact;

    @Column(name = "business_number", length = 20)
    private String businessNumber;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "alert_type")
    private boolean alertType;

    @Column(name = "terms_type")
    private boolean termsType;

    @Column(name = "social_type")
    private boolean socialType;

    @Column(name = "social_name")
    private String socialName;

    @Column(name = "road_address", length = 200)
    private String roadAddress;

    @Column(name = "address_details", length = 200)
    private String addressDetails;
}
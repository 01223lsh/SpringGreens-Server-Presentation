package com.spring_greens.presentation.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller
public class UserViewController {
    @GetMapping("/")
    public String main() { return "main"; }

    @GetMapping("/login")
    public String login() { return "oauthLogin"; }

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code) {
        return "callback";
    }
}
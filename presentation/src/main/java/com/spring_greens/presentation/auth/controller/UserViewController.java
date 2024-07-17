package com.spring_greens.presentation.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UserViewController {
    @GetMapping("/")
    public String main() {
        return "main";
    }

    @GetMapping("/login")
    public String login() { return "oauthLogin"; }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code) {
        return "callback";
    }


}
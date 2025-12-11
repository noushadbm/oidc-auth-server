package com.rayshan.oidc.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class UserInfoController {

    @GetMapping("/userinfo")
    public Map<String, Object> userInfo(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("sub", jwt.getSubject());
        userInfo.put("name", jwt.getClaimAsString("name"));
        userInfo.put("email", jwt.getClaimAsString("email"));
        userInfo.put("preferred_username", jwt.getSubject());
        userInfo.put("email_verified", true);

        return userInfo;
    }
}

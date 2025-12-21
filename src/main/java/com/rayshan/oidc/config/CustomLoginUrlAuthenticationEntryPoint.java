package com.rayshan.oidc.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class CustomLoginUrlAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    public CustomLoginUrlAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        String originalUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();

        if (queryString != null) {
            originalUrl += "?" + queryString;
        }

        // Encode the original URL
        String encodedUrl = URLEncoder.encode(originalUrl, StandardCharsets.UTF_8);

        // Redirect to React login page with continue parameter
        String redirectUrl = getLoginFormUrl() + "?continue=" + encodedUrl;
        response.sendRedirect(redirectUrl);
    }
}

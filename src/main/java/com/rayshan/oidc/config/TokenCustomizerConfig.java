package com.rayshan.oidc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();

            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                // Customize ID Token
                context.getClaims().claim("name", principal.getName());
                context.getClaims().claim("email", principal.getName() + "@example.com");
                context.getClaims().claim("email_verified", true);
                context.getClaims().claim("preferred_username", principal.getName());
            }

            if ("access_token".equals(context.getTokenType().getValue())) {
                // Customize Access Token
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                context.getClaims().claim("authorities", authorities);
                context.getClaims().claim("username", principal.getName());
            }
        };
    }
}

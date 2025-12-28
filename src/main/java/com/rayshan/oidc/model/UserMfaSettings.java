package com.rayshan.oidc.model;

import lombok.Data;

@Data
public class UserMfaSettings {
    private String username;
    private MfaType mfaType;
    private String email;
    private String authenticatorSecret; // For TOTP
    private boolean authenticatorEnabled;
    private boolean emailOtpEnabled;
}

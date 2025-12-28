package com.rayshan.oidc.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MfaResponse {
    private boolean success;
    private String message;
    private boolean mfaRequired;
    private MfaType mfaType;
    private String sessionId;
    private String redirectUrl;
    private boolean emailOtpSent;
    private boolean authenticatorRequired;
}

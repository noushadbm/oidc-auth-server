package com.rayshan.oidc.model;

import lombok.Data;

@Data
public class MfaRequest {
    private String sessionId;
    private String otpCode;
    private MfaVerificationType verificationType; // EMAIL or AUTHENTICATOR
}

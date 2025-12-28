package com.rayshan.oidc.service;

import com.rayshan.oidc.model.MfaType;
import com.rayshan.oidc.model.MfaVerificationType;
import com.rayshan.oidc.model.UserMfaSettings;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Log4j2
public class MfaService {

    // In-memory storage for demo. Use Redis or database in production
    private final Map<String, PendingMfaSession> pendingSessions = new ConcurrentHashMap<>();
    private final Map<String, String> emailOtpStore = new ConcurrentHashMap<>();
    private final Map<String, UserMfaSettings> userMfaSettings = new ConcurrentHashMap<>();

    // Initialize some demo users with different MFA settings
    public MfaService() {
        // User with no MFA
        UserMfaSettings user1 = new UserMfaSettings();
        user1.setUsername("user");
        user1.setMfaType(MfaType.BOTH);
        user1.setEmail("superadmin@example.com");
        user1.setAuthenticatorSecret("JBSWY3DPEHPK3PXP");
        user1.setEmailOtpEnabled(true);
        user1.setAuthenticatorEnabled(true);
//        user1.setMfaType(MfaType.NONE);
        userMfaSettings.put("user", user1);

        // User with email OTP only
        UserMfaSettings user2 = new UserMfaSettings();
        user2.setUsername("admin");
        user2.setMfaType(MfaType.EMAIL_OTP);
        user2.setEmail("admin@example.com");
        user2.setEmailOtpEnabled(true);
        userMfaSettings.put("admin", user2);

        // User with authenticator only
        UserMfaSettings user3 = new UserMfaSettings();
        user3.setUsername("testuser");
        user3.setMfaType(MfaType.AUTHENTICATOR_OTP);
        user3.setAuthenticatorSecret("JBSWY3DPEHPK3PXP"); // Demo secret
        user3.setAuthenticatorEnabled(true);
        userMfaSettings.put("testuser", user3);

        // User with both MFA methods
        UserMfaSettings user4 = new UserMfaSettings();
        user4.setUsername("superadmin");
        user4.setMfaType(MfaType.BOTH);
        user4.setEmail("superadmin@example.com");
        user4.setAuthenticatorSecret("JBSWY3DPEHPK3PXP");
        user4.setEmailOtpEnabled(true);
        user4.setAuthenticatorEnabled(true);
        userMfaSettings.put("superadmin", user4);
    }

    public UserMfaSettings getUserMfaSettings(String username) {
        return userMfaSettings.getOrDefault(username, createDefaultMfaSettings(username));
    }

    private UserMfaSettings createDefaultMfaSettings(String username) {
        UserMfaSettings settings = new UserMfaSettings();
        settings.setUsername(username);
        settings.setMfaType(MfaType.NONE);
        return settings;
    }

    public String createMfaSession(String username, String continueUrl) {
        String sessionId = UUID.randomUUID().toString();
        PendingMfaSession session = new PendingMfaSession();
        session.setUsername(username);
        session.setContinueUrl(continueUrl);
        session.setCreatedAt(System.currentTimeMillis());
        session.setEmailVerified(false);
        session.setAuthenticatorVerified(false);

        pendingSessions.put(sessionId, session);
        return sessionId;
    }

    public PendingMfaSession getMfaSession(String sessionId) {
        return pendingSessions.get(sessionId);
    }

    public void removeMfaSession(String sessionId) {
        pendingSessions.remove(sessionId);
    }

    public String generateEmailOtp(String username) {
        //String otp = String.format("%06d", new SecureRandom().nextInt(999999));
        String otp = "123456"; // For demo purposes
        emailOtpStore.put(username, otp);
        log.info("Generated OTP for {}: {}", username, otp); // In production, don't log OTP
        return otp;
    }

    public boolean verifyEmailOtp(String username, String otp) {
        String storedOtp = emailOtpStore.get(username);
        if (storedOtp != null && storedOtp.equals(otp)) {
            emailOtpStore.remove(username);
            return true;
        }
        return false;
    }

    public boolean verifyAuthenticatorOtp(String username, String otp) {
        UserMfaSettings settings = getUserMfaSettings(username);
        if (settings.getAuthenticatorSecret() == null) {
            return false;
        }

        // Use Google Authenticator library for TOTP verification
        // For now, accepting any 6-digit code for demo
        return otp != null && otp.matches("\\d{6}");
    }

    public boolean isMfaComplete(String sessionId, MfaType requiredMfaType) {
        PendingMfaSession session = pendingSessions.get(sessionId);
        if (session == null) {
            return false;
        }

        switch (requiredMfaType) {
            case NONE:
                return true;
            case EMAIL_OTP:
                return session.isEmailVerified();
            case AUTHENTICATOR_OTP:
                return session.isAuthenticatorVerified();
            case BOTH:
                return session.isEmailVerified() && session.isAuthenticatorVerified();
            default:
                return false;
        }
    }

    public void markVerified(String sessionId, MfaVerificationType type) {
        PendingMfaSession session = pendingSessions.get(sessionId);
        if (session != null) {
            if (type == MfaVerificationType.EMAIL) {
                session.setEmailVerified(true);
            } else if (type == MfaVerificationType.AUTHENTICATOR) {
                session.setAuthenticatorVerified(true);
            }
        }
    }

    @lombok.Data
    public static class PendingMfaSession {
        private String username;
        private String continueUrl;
        private long createdAt;
        private boolean emailVerified;
        private boolean authenticatorVerified;
    }
}

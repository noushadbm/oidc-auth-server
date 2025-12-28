package com.rayshan.oidc.controller;

import com.rayshan.oidc.model.*;
import com.rayshan.oidc.service.EmailService;
import com.rayshan.oidc.service.MfaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000,http://192.168.0.170", allowCredentials = "true")
@Log4j2
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final MfaService mfaService;
    private final EmailService emailService;

    public AuthController(AuthenticationManager authenticationManager,
                          MfaService mfaService,
                          EmailService emailService) {
        this.authenticationManager = authenticationManager;
        this.mfaService = mfaService;
        this.emailService = emailService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest,
                                   @RequestParam(required = false) String continueUrl,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        try {
            log.info("Attempting login for user: {}", loginRequest.getUsername());
            log.info("Continue URL: {}", continueUrl);
            // Create authentication token
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    );

            // Authenticate
            Authentication authentication = authenticationManager.authenticate(authToken);

            // Check MFA requirements
            UserMfaSettings mfaSettings = mfaService.getUserMfaSettings(loginRequest.getUsername());

            if (mfaSettings.getMfaType() == MfaType.NONE) {
                // No MFA required, complete login
                return completeLogin(authentication, request, continueUrl);
            } else {
                // MFA required, create MFA session
                String sessionId = mfaService.createMfaSession(loginRequest.getUsername(), continueUrl);

                // Store preliminary authentication in session
                HttpSession session = request.getSession(true);
                session.setAttribute("PENDING_AUTH", authentication);
                session.setAttribute("MFA_SESSION_ID", sessionId);

                MfaResponse mfaResponse = new MfaResponse();
                mfaResponse.setSuccess(true);
                mfaResponse.setMessage("MFA verification required");
                mfaResponse.setMfaRequired(true);
                mfaResponse.setMfaType(mfaSettings.getMfaType());
                mfaResponse.setSessionId(sessionId);

                // Send email OTP if required
                if (mfaSettings.getMfaType() == MfaType.EMAIL_OTP ||
                        mfaSettings.getMfaType() == MfaType.BOTH) {
                    String otp = mfaService.generateEmailOtp(loginRequest.getUsername());
                    emailService.sendOtpEmail(mfaSettings.getEmail(), otp);
                    mfaResponse.setEmailOtpSent(true);
                }

                // Set flags for authenticator requirement
                if (mfaSettings.getMfaType() == MfaType.AUTHENTICATOR_OTP ||
                        mfaSettings.getMfaType() == MfaType.BOTH) {
                    mfaResponse.setAuthenticatorRequired(true);
                }

                return ResponseEntity.ok(mfaResponse);
            }

//            // Create security context
//            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
//            securityContext.setAuthentication(authentication);
//            SecurityContextHolder.setContext(securityContext);
//
//            // Store security context in session
//            HttpSession session = request.getSession(true);
//            session.setAttribute(
//                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
//                    securityContext
//            );
//
//            return ResponseEntity.ok(new LoginResponse(true, "Login successful", null, continueUrl));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new LoginResponse(false, "Invalid username or password", null, null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new LoginResponse(false, "Authentication failed", e.getMessage(), null));
        }
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestBody MfaRequest mfaRequest,
                                       HttpServletRequest request) {
        try {
            log.info("Verifying MFA for session: {}", mfaRequest.getSessionId());

            MfaService.PendingMfaSession mfaSession = mfaService.getMfaSession(mfaRequest.getSessionId());

            if (mfaSession == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new MfaResponse(false, "Invalid or expired MFA session",
                                false, null, null, null, false, false));
            }

            UserMfaSettings mfaSettings = mfaService.getUserMfaSettings(mfaSession.getUsername());
            boolean verified = false;

            // Verify based on type
            if (mfaRequest.getVerificationType() == MfaVerificationType.EMAIL) {
                verified = mfaService.verifyEmailOtp(mfaSession.getUsername(), mfaRequest.getOtpCode());
                if (verified) {
                    mfaService.markVerified(mfaRequest.getSessionId(), MfaVerificationType.EMAIL);
                }
            } else if (mfaRequest.getVerificationType() == MfaVerificationType.AUTHENTICATOR) {
                verified = mfaService.verifyAuthenticatorOtp(mfaSession.getUsername(), mfaRequest.getOtpCode());
                if (verified) {
                    mfaService.markVerified(mfaRequest.getSessionId(), MfaVerificationType.AUTHENTICATOR);
                }
            }

            if (!verified) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MfaResponse(false, "Invalid OTP code",
                                true, mfaSettings.getMfaType(),
                                mfaRequest.getSessionId(), null, false, false));
            }

            // Check if all required MFA steps are complete
            boolean mfaComplete = mfaService.isMfaComplete(mfaRequest.getSessionId(), mfaSettings.getMfaType());

            if (mfaComplete) {
                // Complete login
                HttpSession session = request.getSession(false);
                if (session == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new MfaResponse(false, "Session expired",
                                    false, null, null, null, false, false));
                }

                Authentication authentication = (Authentication) session.getAttribute("PENDING_AUTH");
                if (authentication == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new MfaResponse(false, "Authentication not found",
                                    false, null, null, null, false, false));
                }

                // Complete the login
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);

                session.setAttribute(
                        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                        securityContext
                );

                // Clean up
                session.removeAttribute("PENDING_AUTH");
                session.removeAttribute("MFA_SESSION_ID");
                mfaService.removeMfaSession(mfaRequest.getSessionId());

                MfaResponse response = new MfaResponse();
                response.setSuccess(true);
                response.setMessage("MFA verification successful");
                response.setMfaRequired(false);
                response.setRedirectUrl(mfaSession.getContinueUrl());

                return ResponseEntity.ok(response);
            } else {
                // More MFA steps required
                MfaResponse response = new MfaResponse();
                response.setSuccess(true);
                response.setMessage("Verification successful, additional MFA required");
                response.setMfaRequired(true);
                response.setMfaType(mfaSettings.getMfaType());
                response.setSessionId(mfaRequest.getSessionId());

                // Indicate which verification is still needed
                response.setEmailOtpSent(!mfaSession.isEmailVerified() &&
                        (mfaSettings.getMfaType() == MfaType.EMAIL_OTP ||
                                mfaSettings.getMfaType() == MfaType.BOTH));
                response.setAuthenticatorRequired(!mfaSession.isAuthenticatorVerified() &&
                        (mfaSettings.getMfaType() == MfaType.AUTHENTICATOR_OTP ||
                                mfaSettings.getMfaType() == MfaType.BOTH));

                return ResponseEntity.ok(response);
            }

        } catch (Exception e) {
            log.error("MFA verification error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MfaResponse(false, "MFA verification failed",
                            false, null, null, null, false, false));
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestParam String sessionId) {
        try {
            MfaService.PendingMfaSession mfaSession = mfaService.getMfaSession(sessionId);

            if (mfaSession == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "message", "Invalid session"));
            }

            UserMfaSettings mfaSettings = mfaService.getUserMfaSettings(mfaSession.getUsername());

            if (mfaSettings.isEmailOtpEnabled()) {
                String otp = mfaService.generateEmailOtp(mfaSession.getUsername());
                emailService.sendOtpEmail(mfaSettings.getEmail(), otp);
                return ResponseEntity.ok(Map.of("success", true, "message", "OTP resent successfully"));
            }

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("success", false, "message", "Email OTP not enabled"));

        } catch (Exception e) {
            log.error("Resend OTP error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "Failed to resend OTP"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(new LoginResponse(true, "Logout successful", null, null));
    }

    private ResponseEntity<?> completeLogin(Authentication authentication,
                                            HttpServletRequest request,
                                            String continueUrl) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        HttpSession session = request.getSession(true);
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                securityContext
        );

        return ResponseEntity.ok(new LoginResponse(true, "Login successful", null, continueUrl));
    }
}

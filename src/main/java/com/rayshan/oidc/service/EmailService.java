package com.rayshan.oidc.service;

import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

@Service
@Log4j2
public class EmailService {

    public void sendOtpEmail(String email, String otp) {
        // In production, integrate with actual email service (SendGrid, AWS SES, etc.)
        log.info("Sending OTP {} to email: {}", otp, email);

        // Mock email sending
        log.info("Email sent successfully (mock)");
    }
}

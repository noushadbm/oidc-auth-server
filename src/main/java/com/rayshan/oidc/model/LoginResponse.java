package com.rayshan.oidc.model;

public class LoginResponse {
    private boolean success;
    private String message;
    private String error;
    private String redirectUrl;

    public LoginResponse(boolean success, String message, String error, String redirectUrl) {
        this.success = success;
        this.message = message;
        this.error = error;
        this.redirectUrl = redirectUrl;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
}

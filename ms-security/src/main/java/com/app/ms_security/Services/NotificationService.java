package com.app.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class NotificationService {

    @Value("${notification.service.url}")
    private String notificationServiceUrl;

    public String generateCode2FA() {
        int code = (int)(Math.random() * 900000) + 100000; //
        return String.valueOf(code);
    }

    public void send2FACode(String email, String code) {
        RestTemplate restTemplate = new RestTemplate();
        String url = notificationServiceUrl + "/send";
        Map<String, String> request = new HashMap<>();
        request.put("email", email);
        request.put("subject", "Tu código de verificación 2FA");
        request.put("message", "Tu código de verificación es: " + code);
        restTemplate.postForObject(url, request, String.class);
    }

    public void sendLoginNotification(String email, String userName, String loginTime) {
        RestTemplate restTemplate = new RestTemplate();
        String url = notificationServiceUrl + "/login";
        Map<String, String> request = new HashMap<>();
        request.put("email", email);
        request.put("user_name", userName);
        request.put("login_time", loginTime);
        restTemplate.postForObject(url, request, String.class);
    }
}
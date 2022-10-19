package com.whq.security.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.whq")
public class SecurityOAuth2Application {
    public static void main(String[] args) {
        SpringApplication.run(SecurityOAuth2Application.class, args);
    }
}

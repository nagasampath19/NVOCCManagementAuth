package com.authapi.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.authapi.auth.util.JwtUtil;

@Service
public class TokenValidationService {

    private static final Logger logger = LoggerFactory.getLogger(TokenValidationService.class);

    @Autowired
    private JwtUtil jwtUtil;

    public boolean validateToken(String token) {
        try {
            String username = jwtUtil.getUsernameFromToken(token);
            return username != null && !jwtUtil.isTokenExpired(token);
        } catch (Exception e) {
            logger.error("Error validating token", e);
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        return jwtUtil.isTokenExpired(token);
    }

    public String renewToken(String token) {
        return jwtUtil.renewToken(token);
    }
}

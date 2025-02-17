package com.authapi.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authapi.auth.DTOs.AuthenticationRequest;
import com.authapi.auth.DTOs.AuthenticationResponse;
import com.authapi.auth.model.Users;
import com.authapi.auth.repository.UserRepository;
import com.authapi.auth.service.MyUserDetailsService;
import com.authapi.auth.service.TokenValidationService;
import com.authapi.auth.util.JwtUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository; // For user registration

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenValidationService tokenValidationService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody Users userDetail) {
        // Hash the password
        String hashedPassword = passwordEncoder.encode(userDetail.getPassword());
        userDetail.setPassword(hashedPassword);

        userRepository.save(userDetail);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getUsername(), authenticationRequest.getPassword()
                    )
            );
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        Users user = userRepository.findByUsername(authenticationRequest.getUsername());
        String token = jwtUtil.generateToken(userDetails, user.getId());

        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authorizationHeader) {
        // Extract the token from the Authorization header
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Authorization header");
        }
        
        String token = authorizationHeader.substring(7);
        
        // Check if the token is null or empty
        if (token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is null or empty");
        }
        
        // Invalidate the token by setting its expiration to the past
        jwtUtil.invalidateToken(token);
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Extract token

            if (tokenValidationService.validateToken(token)) {
                if (tokenValidationService.isTokenExpired(token)) {
                    return ResponseEntity.status(401).body("Token is expired");
                }

                // Renew the token
                String renewedToken = tokenValidationService.renewToken(token);
                return ResponseEntity.ok().header("Authorization", "Bearer " + renewedToken).body("Token is valid");
            }
        }
        return ResponseEntity.status(401).body("Invalid token");
    }
}

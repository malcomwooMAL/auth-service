package com.example.authservice.controller;

import com.example.authservice.dto.UserDto;
import com.example.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Endpoints for user registration and login")
public class AuthController {

    private final AuthService authService;
    private final RestTemplate restTemplate;

    public AuthController(AuthService authService) {
        this.authService = authService;
        this.restTemplate = new RestTemplate();
    }

    @PostMapping("/registrar")
    @Operation(summary = "Register a new user")
    @ApiResponse(responseCode = "200", description = "User registered successfully")
    public ResponseEntity<?> registerUser(@RequestBody UserDto userDto) {
        authService.registerNewUser(userDto);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    @Operation(summary = "Login as a user")
    @ApiResponse(responseCode = "200", description = "User logged in successfully")
    public ResponseEntity<?> login(@RequestBody UserDto userDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("client", "secret");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("username", userDto.getUsername());
        map.add("password", userDto.getPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        return restTemplate.exchange("http://localhost:8080/oauth2/token", HttpMethod.POST, request, String.class);
    }
}

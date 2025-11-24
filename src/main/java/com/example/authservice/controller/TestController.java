package com.example.authservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Tag(name = "Testing", description = "Endpoints for testing authentication")
public class TestController {

    @GetMapping("/dados-protegidos")
    @Operation(summary = "Access a protected endpoint")
    @ApiResponse(responseCode = "200", description = "Successfully accessed protected endpoint")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<String> testEndpoint() {
        return ResponseEntity.ok("This is a protected endpoint.");
    }
}

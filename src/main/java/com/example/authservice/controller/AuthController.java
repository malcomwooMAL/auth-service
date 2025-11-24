package com.example.authservice.controller;

import com.example.authservice.dto.UserDto;
import com.example.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
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

/**
 * Controlador responsável pelos endpoints de autenticação.
 */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Autenticação", description = "Endpoints para registro de usuário e login")
public class AuthController {

    private final AuthService authService;
    private final RestTemplate restTemplate;

    public AuthController(AuthService authService) {
        this.authService = authService;
        this.restTemplate = new RestTemplate();
    }

    /**
     * Endpoint para registrar um novo usuário.
     *
     * @param userDto Objeto contendo username e password.
     * @return Mensagem de sucesso.
     */
    @PostMapping("/registrar")
    @Operation(summary = "Registrar um novo usuário", description = "Cria um novo usuário no sistema com os dados fornecidos.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuário registrado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Dados inválidos fornecidos", content = @Content),
            @ApiResponse(responseCode = "500", description = "Erro interno no servidor", content = @Content)
    })
    public ResponseEntity<?> registerUser(@RequestBody UserDto userDto) {
        authService.registerNewUser(userDto);
        return ResponseEntity.ok("User registered successfully");
    }

    /**
     * Endpoint para realizar login.
     * Este endpoint atua como um proxy para o endpoint de token do OAuth2.
     *
     * @param userDto Objeto contendo username e password.
     * @return Token de acesso OAuth2.
     */
    @PostMapping("/login")
    @Operation(summary = "Realizar login", description = "Autentica o usuário e retorna um token de acesso. Este endpoint faz uma chamada interna para o fluxo OAuth2.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login realizado com sucesso. Retorna o token de acesso.",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "401", description = "Credenciais inválidas", content = @Content)
    })
    public ResponseEntity<?> login(@RequestBody UserDto userDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("client", "secret");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("username", userDto.getUsername());
        map.add("password", userDto.getPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        return restTemplate.exchange("http://localhost:9000/oauth2/token", HttpMethod.POST, request, String.class);
    }
}

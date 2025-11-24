package com.example.authservice.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Data Transfer Object (DTO) para representar as informações do usuário.
 * Utilizado para registro e login.
 */
public class UserDto {

    @Schema(description = "Nome de usuário para autenticação", example = "usuario123")
    private String username;

    @Schema(description = "Senha do usuário", example = "minhasenhaforte")
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

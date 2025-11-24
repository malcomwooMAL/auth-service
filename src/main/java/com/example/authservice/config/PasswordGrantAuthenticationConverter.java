package com.example.authservice.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = getParameters(request);
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        Set<String> scopes = new HashSet<>(
                Arrays.asList(StringUtils.delimitedListToStringArray(parameters.getFirst(OAuth2ParameterNames.SCOPE), " ")));

        Map<String, Object> additionalParameters = parameters.entrySet().stream()
                .filter(e -> !OAuth2ParameterNames.GRANT_TYPE.equals(e.getKey()) &&
                        !OAuth2ParameterNames.SCOPE.equals(e.getKey()) &&
                        !OAuth2ParameterNames.PASSWORD.equals(e.getKey()) &&
                        !OAuth2ParameterNames.USERNAME.equals(e.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get(0)));

        return new PasswordGrantAuthenticationToken(
                (OAuth2ClientAuthenticationToken) clientPrincipal, 
                username, 
                password, 
                scopes, 
                additionalParameters);
    }

    private MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new org.springframework.util.LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
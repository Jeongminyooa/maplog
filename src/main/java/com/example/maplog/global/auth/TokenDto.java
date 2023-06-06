package com.example.maplog.global.auth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenDto {
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private Long tokenValidityMilliseconds;
}

package com.example.maplog.domain.user;

import lombok.Data;

public class LoginDto {
    @Data
    public class LoginRequestDto {
        private String id;
        private String pwd;
    }
}

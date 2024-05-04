package com.demo.springsecurity.utils;

import com.auth0.jwt.interfaces.Claim;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author: Yupeng Li
 * @Date: 18/4/2024 19:15
 * @Description:
 */
@SpringBootTest
public class TokenTest {

    @Test
    public void testGenToken() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", "12345");
        claims.put("username", "johndoe");
        claims.put("email", "john.doe@example.com");
        claims.put("role", "admin");
        claims.put("verified", true);

        String s = JwtUtil.genToken(claims);
        System.out.println(s);

    }

    @Test
    public void testParseToken() {
        String token ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyQ2xhaW1zIjp7InN0dWRlbnRJRCI6MSwidXNlcm5hbWUiOiJ0ZXN0In0sImlzcyI6Im9zLXdvbWJhdCIsImlhdCI6MTcxMzQzNDY5NCwiZXhwIjoxNzEzNTIxMDk0fQ.s8FdsDJuhDbLa5YubpY3fzBPBS6P1Hx7qTcP5aQ5k8o";
        Claim claim = JwtUtil.parseToken(token);
        System.out.println(claim);
    }

}

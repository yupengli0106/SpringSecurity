package com.demo.springsecurity.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.Map;

public class JwtUtil {

    private static final String SECRET_KEY = "***I bet you can't guess this secret key :)***";
    private static final String ISSUER = "os-wombat"; // application name
    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 24h


    /**
     * 生成token
     * @param claims 业务数据 例如用户id 用户名等
     * @return token
     */
    public static String genToken(Map<String, Object> claims) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY); // 使用密钥初始化算法
            return JWT.create()
                    .withClaim("userClaims", claims) // 更明确地命名claims
                    .withIssuer(ISSUER) // 添加发行者
                    .withIssuedAt(new Date()) // 添加令牌发行时间
                    .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))// 添加过期时间
                    .sign(algorithm); // 签名
        } catch (Exception e) {
            throw new RuntimeException("Error generating token", e);
        }
    }


    /**
     * 解析token
     * @param token token
     * @return 用户信息 claims 转换为map返回
     */
//    public static Map<String, Object> parseToken(String token) {
//        try {
//            // 使用同一个密钥和算法初始化一个JWT验证器
//            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
//            JWTVerifier verifier = JWT.require(algorithm)
//                    .withIssuer(ISSUER)  // 如果在生成token时指定了发行者，这里需要检查
//                    .build();// Reusable verifier instance
//
//            // 使用验证器验证token
//            DecodedJWT jwt = verifier.verify(token);
//            return jwt.getClaim("userClaims").asMap();
//        } catch (Exception e) {
//            throw new RuntimeException("Error parsing token", e);
//        }
//    }

    public static Claim parseToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY); // 使用相同的密钥初始化算法
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(ISSUER)
                    .build(); // 创建JWT验证器

            DecodedJWT jwt = verifier.verify(token); // 使用验证器验证并解码JWT

            return jwt.getClaim("userClaims"); // 返回用户信息
        } catch (JWTVerificationException e) {
            // JWT验证失败，可能是因为签名不匹配、过期等原因
            // 在这里可以记录日志或者其他适当的处理
            e.printStackTrace();
            throw new RuntimeException("Error parsing token", e);

        }
    }


}

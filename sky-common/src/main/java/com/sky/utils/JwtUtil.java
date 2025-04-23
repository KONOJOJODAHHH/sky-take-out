package com.sky.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

public class JwtUtil {
    /**
     * 生成jwt
     * 使用Hs256算法, 私匙使用固定秘钥
     *
     * @param secretKey jwt秘钥
     * @param ttlMillis jwt过期时间(毫秒)
     * @param claims    设置的信息
     * @return String
     */
    public static String createJWT(String secretKey, long ttlMillis, Map<String, Object> claims) {
        // 指定签名的时候使用的签名算法，也就是header那部分
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // 生成JWT的时间
        long expMillis = System.currentTimeMillis() + ttlMillis;
        Date exp = new Date(expMillis);

        // 确保使用安全的密钥
        // 如果secretKey长度不够，使用它作为种子生成足够长度的密钥
        SecretKey key = getSecureKey(secretKey);

        // 设置jwt的body
        JwtBuilder builder = Jwts.builder()
                // 如果有私有声明，一定要先设置这个自己创建的私有的声明，这个是给builder的claim赋值，一旦写在标准的声明赋值之后，就是覆盖了那些标准的声明的
                .setClaims(claims)
                // 使用安全密钥进行签名
                .signWith(key)
                // 设置过期时间
                .setExpiration(exp);

        return builder.compact();
    }

    /**
     * Token解密
     *
     * @param secretKey jwt秘钥 此秘钥一定要保留好在服务端, 不能暴露出去, 否则sign就可以被伪造, 如果对接多个客户端建议改造成多个
     * @param token     加密后的token
     * @return Claims
     */
    public static Claims parseJWT(String secretKey, String token) {
        // 确保使用相同的安全密钥
        SecretKey key = getSecureKey(secretKey);

        // 使用更新的API
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }

    /**
     * 获取安全的密钥
     *
     * @param secretKey 原始密钥字符串
     * @return 安全的密钥对象
     */
    private static SecretKey getSecureKey(String secretKey) {
        // 如果原始密钥足够长（至少32个字符/256位），直接使用
        if (secretKey.length() >= 32) {
            return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        } else {
            // 如果密钥太短，使用它作为种子扩展成足够长的密钥
            // 注意：在生产环境中应使用更安全的方式生成密钥
            StringBuilder extendedKey = new StringBuilder(secretKey);
            while (extendedKey.length() < 32) {
                extendedKey.append(secretKey);
            }
            return Keys.hmacShaKeyFor(extendedKey.substring(0, 32).getBytes(StandardCharsets.UTF_8));
        }
    }
}
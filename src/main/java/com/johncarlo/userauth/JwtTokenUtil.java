package com.johncarlo.userauth;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenUtil {

    SecretKey key = Jwts.SIG.HS256.key().build();

    public String generateToken(String email) {
        Date issuedAt = new Date();
        Date expiryDate = new Date(issuedAt.getTime() + 10000);
//        Date expiryDate = new Date(issuedAt.getTime() + 86400000);
        return Jwts.builder()
                .subject(email)
                .issuedAt(issuedAt)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getEmailFromToken(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
    }


}

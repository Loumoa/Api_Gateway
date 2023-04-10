package fr.loumoa.gateway.security.jwt;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;

@Component
public class JwtUtils {
    @Value("${app.publicToken.url}")
    private String publicTokenUrl;

    @Value("${app.public-key.cache}")
    private boolean cacheEnable;

    @Value("${app.public-key.cache-duration}")
    private int cacheDuration;

    private PublicKey publicKey;

    private Long expirationTime;

    private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (cacheEnable){
            if (expirationTime != null){
                if (System.currentTimeMillis() < expirationTime){
                    return publicKey;
                }
            }
            publicKey = retrievePublicKey();
            expirationTime = System.currentTimeMillis() + (cacheDuration * 1000L);
            return publicKey;
        }else {
            return retrievePublicKey();
        }
    }

    private PublicKey retrievePublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.getForEntity(URI.create(publicTokenUrl), Map.class);

        if(response.getStatusCode().is2xxSuccessful() && response.hasBody()){
            String base64PublicKey = (String) response.getBody().get("token");
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        }
        return null;
    }

    public boolean validateJwtToken(String authToken) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            Jwts.parser().setSigningKey(getPublicKey()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            System.err.println("Invalid JWT signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.err.println("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.err.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.err.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }

    public UserInfos getUserInfos(String token) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Claims jwtBody = Jwts.parser().setSigningKey(getPublicKey()).parseClaimsJws(token).getBody();
        return new UserInfos(
                jwtBody.get("userId", Integer.class),
                jwtBody.getSubject(),
                jwtBody.get("email", String.class),
                jwtBody.get("roles", List.class)
        );
    }
}

package be.bastinjul.securitypreauthheader.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class JwtUtils {
    private JwtUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static String constructJwt(String username, String additionalInfo, List<String> roles) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = generator.generateKeyPair();
        return JWT.create()
                .withSubject(username)
                .withClaim("additionalInfo", additionalInfo)
                .withClaim("roles", roles)
                .sign(Algorithm.RSA256((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate()));
    }
}

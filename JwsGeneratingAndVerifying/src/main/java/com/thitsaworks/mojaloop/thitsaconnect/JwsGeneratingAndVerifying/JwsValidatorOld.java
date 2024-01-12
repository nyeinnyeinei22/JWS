package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.logging.Logger;

@Component
public class JwsValidatorOld {

    @Value("${jwt.secret}")
    private String secret;

    @Autowired
    private RSAKeyProvider rsaKeyProvider;
    private static final Logger LOGGER = Logger.getLogger(JwsValidatorOld.class.getName());
    private static final JWSAlgorithm SIGNATURE_ALGORITHM = JWSAlgorithm.RS256;

    /**
     * Validates the JWS headers on an incoming HTTP request
     * Throws if the protected header or signature are not valid
     */
    public boolean validate(String request) throws Exception {
        boolean bIsValid = true;
        try {

            String validationKeys = secret;

            String jws = request.replace("Bearer ", "");  //request.getHeader("Authorization").replace("Bearer ", "");
            SignedJWT signedJWT = SignedJWT.parse(jws);
            JWSHeader header = signedJWT.getHeader();
            if (!header.getAlgorithm().equals(SIGNATURE_ALGORITHM)) {
                bIsValid = false;
                throw new Exception("Invalid signature algorithm");
            }
            String keyId = header.getKeyID();
            if (!header.getKeyID().equals(validationKeys)) {
                bIsValid = false;
                throw new Exception("Invalid key ID");
            }
            //String publicKey = validationKeys.get(keyId);
            PublicKey publicKey = rsaKeyProvider.getPublicKeyRsa(keyId);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            if (!signedJWT.verify(verifier)) {
                bIsValid = false;
                throw new Exception("Invalid signature");
            }
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet.getExpirationTime().before(new Date())) {
                bIsValid = false;
                throw new Exception("Token expired");
            }
        } catch (JOSEException e) {
            bIsValid = false;
            LOGGER.severe("Error validating JWS: " + e.getMessage());
            throw new Exception("Error validating JWS");
        }
        return bIsValid;
    }


}

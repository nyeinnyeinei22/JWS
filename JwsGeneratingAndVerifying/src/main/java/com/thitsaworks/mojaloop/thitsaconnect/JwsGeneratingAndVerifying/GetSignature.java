package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class GetSignature {

    @Value("${jwt.secret}")
    private String secret;

    @Autowired
    private RSAKeyProvider rsaKeyProvider;

    private static final Logger logger = Logger.getLogger(GetSignature.class.getName());

    private static final String SIGNATURE_ALGORITHM = "RS256";

    private static final Pattern uriRegex = Pattern.compile(
            "(?:^.*)(\\/(participants|parties|quotes|bulkQuotes|transfers|bulkTransfers|transactionRequests|thirdpartyRequests|authorizations|consents|consentRequests|)(\\/.*?)*)$");

    private static final Base64.Encoder base64Encoder = Base64.getEncoder();

    private static final Base64.Decoder base64Decoder = Base64.getDecoder();

    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    public String getSignature(Map<String, String> requestOptions)
            throws Exception {

        PublicKey publicKey = rsaKeyProvider.readX509PublicKey(
                "jwsValidationKey.pem"); //C:\\NNEWORKING\\Mojaloop\\sdk-standard-components\\test\\unit\\data\\jwsValidationKey.pem"
        PrivateKey privateKey = rsaKeyProvider.readPKCS8PrivateKey(
                "jwsSigningKey.pem"); //C:\\NNEWORKING\\Mojaloop\\sdk-standard-components\\test\\unit\\data\\jwsSigningKey.pem
        Algorithm signingKey =
                Algorithm.RSA256((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey); //HMAC256(secret);

        logger.info(String.format("Get JWS Signature: %s", requestOptions));
        String payload = requestOptions.get("body") != null ? requestOptions.get("body") : requestOptions.get("data");
        String uri = requestOptions.get("uri") != null ? requestOptions.get("uri") : requestOptions.get("url");

        if (payload == null) {
            throw new IllegalArgumentException("Cannot sign with no body");
        }

        Matcher uriMatches = uriRegex.matcher(uri.toString());
        if (!uriMatches.matches() || uriMatches.groupCount() < 2) {
            throw new IllegalArgumentException(String.format("URI not valid for protected header: %s", uri));
        }

        // generate the protected header as base64url encoding of UTF-8 encoding of JSON string
        Map<String, Object> protectedHeaderObject = new HashMap<>();
        protectedHeaderObject.put("alg", SIGNATURE_ALGORITHM);
        protectedHeaderObject.put("FSPIOP-URI", requestOptions.get("FSPIOP-URI"));
        protectedHeaderObject.put("FSPIOP-HTTP-Method",
                requestOptions.get("FSPIOP-HTTP-Method").toString().toUpperCase());
        protectedHeaderObject.put("FSPIOP-Source", requestOptions.get("FSPIOP-Source"));
        //protectedHeaderObject.put("kid", secret);

        // set destination in the protected header object if it is present in the request headers
        if (requestOptions.get("FSPIOP-Destination") != null) {
            protectedHeaderObject.put("FSPIOP-Destination", requestOptions.get("FSPIOP-Destination"));
        }

        // set date in the protected header object if it is present in the request headers
        if (requestOptions.get("Date") != null) {
            protectedHeaderObject.put("Date", requestOptions.get("Date"));
        }

        Map<String, Object> claims = new HashMap<>();
        if (requestOptions.get("body") != null || requestOptions.get("data") != null) {
            claims.put("body",
                    requestOptions.get("body") != null ? requestOptions.get("body") : requestOptions.get("data"));
        }

        // now we sign
        //String token = JWT.create().withHeader(protectedHeaderObject).withPayload(claims).sign(signingKey);

        String token = Jwts.builder().setClaims(claims)
                           .setSubject(protectedHeaderObject.toString())
                           .setIssuedAt(new Date(System.currentTimeMillis()))
                           .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                           .signWith(SignatureAlgorithm.RS256, privateKey)
                           .compact();

        // now set the signature header as JSON encoding of the signature and protected header as per mojaloop spec
        String[] parts = token.split("\\.");
        String protectedHeaderBase64 = parts[0];
        String signature = parts[2];

        Map<String, String> signatureObject = new HashMap<>();
        signatureObject.put("signature", signature.replace("\"", ""));
        signatureObject.put("protectedHeader", protectedHeaderBase64.replace("\"", ""));
        signatureObject.put("token", token);

        return signatureObject.toString();
    }

}

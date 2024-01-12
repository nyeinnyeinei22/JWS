import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class VerifyJwtToken {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, JsonProcessingException {
        //TODO: Replace your generated JWT token here
        var jwt = "...";
        var claims = parse(jwt);
        var obM = new ObjectMapper();
        var claimsPretty = obM.writerWithDefaultPrettyPrinter().writeValueAsString(claims);
        System.out.println(claimsPretty);
    }

    private static Jws<Claims> parse(String jwsString) {
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKeyRsa();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        var claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwsString);
        System.out.println(claims);
        return claims;
    }


    private static PublicKey getPublicKeyRsa() throws NoSuchAlgorithmException, InvalidKeySpecException {
        //TODO : Replace your public key here
        String rsaPublicKey = "-----BEGIN RSA PUBLIC KEY-----"
                + "..."
                + "-----END RSA PUBLIC KEY-----";

        rsaPublicKey = rsaPublicKey.replace("-----BEGIN RSA PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END RSA PUBLIC KEY-----", "");

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(keySpec);

        return publicKey;
    }
}
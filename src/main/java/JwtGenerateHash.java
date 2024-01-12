import com.fasterxml.jackson.core.JsonProcessingException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class JwtGenerateHash {

    static String hash() throws NoSuchAlgorithmException, JsonProcessingException {
        var header = JwtCreateHeader.createJwtHeader();
        var payload = JwtCreatePayload.createJWtPayload();

        var input = header + "." + payload;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] result = md.digest(input.getBytes());
        var hash = Base64.getEncoder().encodeToString(result);
        return hash;
    }

} 
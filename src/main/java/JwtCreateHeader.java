import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.HashMap;


public class JwtCreateHeader {

    static String createJwtHeader() throws JsonProcessingException {
        var header = "";
        var headerMap = new HashMap<String, String>();
        //TODO 1: Specify the algorithm
        headerMap.put("alg", "RS256");
        headerMap.put("typ", "JWT");
        var objectMapper = new ObjectMapper();
        var headerJson = objectMapper.writeValueAsString(headerMap);
        header = Base64.getUrlEncoder().encodeToString(headerJson.getBytes());
        return Utils.convertToBase64Url(header);
    }

} 
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.HashMap;


public class JwtCreatePayload {

    static String createJWtPayload() throws JsonProcessingException {
        var payload = "";
        var payloadMap = new HashMap<String, Object>();
        //TODO 2: Specify your claims below, duplicate the field below if multiple claims are required.
        payloadMap.put("<insert claim>", "<insert value>");
        var objectMapper = new ObjectMapper();
        var payloadJson = objectMapper.writeValueAsString(payloadMap);
        payload = Base64.getUrlEncoder().encodeToString(payloadJson.getBytes());
        return Utils.convertToBase64Url(payload);

    }
}
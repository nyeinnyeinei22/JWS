public class Utils {

    static String convertToBase64Url(String base64String) {
        var base64UrlString = base64String.replace("+", "-");
        base64UrlString = base64UrlString.replace("/", "_");
        base64UrlString = base64UrlString.replace("=", "");
        return base64UrlString;
    }
}

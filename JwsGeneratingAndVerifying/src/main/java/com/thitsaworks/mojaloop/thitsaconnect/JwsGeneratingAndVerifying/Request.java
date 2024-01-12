package com.thitsaworks.mojaloop.thitsaconnect.JwsGeneratingAndVerifying;

import java.util.Map;

public class Request {
    private Map<String, String> headers;
    private String body;
    private Object data;

    public Request(Map<String, String> headers, String body, Object data) {
        this.headers = headers;
        this.body = body;
        this.data = data;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public Object getData() {
        return data;
    }
}
// com.apisecurity.analyzer.executor/ApiCallResult.java
package com.apisecurity.analyzer.executor;

public class ApiCallResult {
    public final int statusCode;
    public final String responseBody;
    public final Exception error;

    public ApiCallResult(int statusCode, String responseBody) {
        this.statusCode = statusCode;
        this.responseBody = responseBody;
        this.error = null;
    }

    public ApiCallResult(Exception error) {
        this.statusCode = -1;
        this.responseBody = null;
        this.error = error;
    }

    public boolean isSuccess() {
        return error == null && statusCode >= 200 && statusCode < 300;
    }
}
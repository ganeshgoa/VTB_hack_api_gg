// com.apisecurity.analyzer.graph/DependencyEdge.java
package com.apisecurity.analyzer.graph;

/**
 * Ребро зависимости: откуда берётся параметр.
 */
public class DependencyEdge {
    public final String sourceEndpointKey;  // "GET /accounts"
    public final String targetEndpointKey;  // "GET /accounts/{account_id}"
    public final String parameterName;      // "account_id"

    public DependencyEdge(String source, String target, String param) {
        this.sourceEndpointKey = source;
        this.targetEndpointKey = target;
        this.parameterName = param;
    }

    @Override
    public String toString() {
        return String.format("[%s] --(%s)--> [%s]", sourceEndpointKey, parameterName, targetEndpointKey);
    }
}
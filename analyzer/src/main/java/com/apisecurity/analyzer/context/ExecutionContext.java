// com.apisecurity.analyzer.context/ExecutionContext.java
package com.apisecurity.analyzer.context;

import java.util.*;

/**
 * Контекст выполнения: хранит все известные параметры для динамического анализа.
 */
public class ExecutionContext {
    private final Map<String, Object> values = new LinkedHashMap<>();

    public void provide(String key, Object value) {
        if (value != null) {
            this.values.put(key, value);
        }
    }

    public boolean has(String key) {
        return this.values.containsKey(key);
    }

    public Object get(String key) {
        return this.values.get(key);
    }

    public Map<String, Object> getAll() {
        return new LinkedHashMap<>(this.values);
    }

    public Set<String> getKeys() {
        return this.values.keySet();
    }

    @Override
    public String toString() {
        return "ExecutionContext" + values;
    }
}
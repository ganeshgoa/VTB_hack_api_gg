package com.apisecurity.shared;
import com.apisecurity.shared.ModuleResult;
import com.apisecurity.shared.EndpointAnalysis;
import java.util.*;

public class ModuleResult {
    private String status;
    private List<String> findings;
    private Map<String, Object> details;
    private long executionTime;
    
    public ModuleResult() {
        this.findings = new ArrayList<>();
        this.details = new HashMap<>();
        this.status = "PENDING";
    }
    
    public ModuleResult(String status) {
        this();
        this.status = status;
    }
    
    // Геттеры и сеттеры
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public List<String> getFindings() { return findings; }
    public void setFindings(List<String> findings) { this.findings = findings; }
    public void addFinding(String finding) { this.findings.add(finding); }
    
    public Map<String, Object> getDetails() { return details; }
    public void setDetails(Map<String, Object> details) { this.details = details; }
    public void addDetail(String key, Object value) { this.details.put(key, value); }
    
    public long getExecutionTime() { return executionTime; }
    public void setExecutionTime(long executionTime) { this.executionTime = executionTime; }
    
    @Override
    public String toString() {
        return String.format("ModuleResult{status='%s', findings=%d, executionTime=%dms}", 
                           status, findings.size(), executionTime);
    }
}
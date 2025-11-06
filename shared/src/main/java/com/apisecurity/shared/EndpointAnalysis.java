package com.apisecurity.shared;
import com.apisecurity.shared.ModuleResult;
import com.apisecurity.shared.EndpointAnalysis;
public class EndpointAnalysis {
    private String endpointName;
    private int endpointNumber;
    private String input;
    private String validator;
    private String analyzer;
    private String ai;
    private String testing;
    private String reportmaker;
    private String recommendation;
    
    public EndpointAnalysis() {}
    
    public EndpointAnalysis(String endpointName, int endpointNumber) {
        this.endpointName = endpointName;
        this.endpointNumber = endpointNumber;
        this.input = endpointName;
    }
    
    // Геттеры и сеттеры
    public String getEndpointName() { return endpointName; }
    public void setEndpointName(String endpointName) { this.endpointName = endpointName; }
    
    public int getEndpointNumber() { return endpointNumber; }
    public void setEndpointNumber(int endpointNumber) { this.endpointNumber = endpointNumber; }
    
    public String getInput() { return input; }
    public void setInput(String input) { this.input = input; }
    
    public String getValidator() { return validator; }
    public void setValidator(String validator) { this.validator = validator; }
    
    public String getAnalyzer() { return analyzer; }
    public void setAnalyzer(String analyzer) { this.analyzer = analyzer; }
    
    public String getAi() { return ai; }
    public void setAi(String ai) { this.ai = ai; }
    
    public String getTesting() { return testing; }
    public void setTesting(String testing) { this.testing = testing; }
    
    public String getReportmaker() { return reportmaker; }
    public void setReportmaker(String reportmaker) { this.reportmaker = reportmaker; }
    
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    
    @Override
    public String toString() {
        return String.format("EndpointAnalysis{endpointName='%s', endpointNumber=%d}", 
                           endpointName, endpointNumber);
    }
}
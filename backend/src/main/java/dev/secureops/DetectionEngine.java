package dev.secureops;

public class DetectionEngine {
  public record Match(String ruleKey, String title, String severity) {}
  public Match evaluate(String category, String description, long recentFailedLogins) {
    if ("PRIVILEGE_CHANGE".equalsIgnoreCase(category)) return new Match("PRIVILEGE_CHANGE", "Privileged access changed", "CRITICAL");
    if (description != null && description.toLowerCase().contains("successful login") && recentFailedLogins >= 5)
      return new Match("LOGIN_FAILURE_THEN_SUCCESS", "Successful login after repeated failures", "HIGH");
    return null;
  }
}

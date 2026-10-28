package dev.secureops;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineTest {
  private final DetectionEngine engine = new DetectionEngine();
  @Test void detectsPrivilegeChangesAsCritical() {
    var match=engine.evaluate("PRIVILEGE_CHANGE","Synthetic role update",0);
    assertNotNull(match); assertEquals("CRITICAL",match.severity());
  }
  @Test void detectsSuccessAfterFiveFailures() {
    var match=engine.evaluate("AUTHENTICATION","Synthetic successful login",5);
    assertNotNull(match); assertEquals("LOGIN_FAILURE_THEN_SUCCESS",match.ruleKey());
  }
  @Test void ignoresSuccessBelowFailureThreshold() {
    assertNull(engine.evaluate("AUTHENTICATION","Synthetic successful login",4));
  }
  @Test void ignoresOrdinaryActivity() {
    assertNull(engine.evaluate("AUTHENTICATION","Synthetic normal login",0));
  }
}

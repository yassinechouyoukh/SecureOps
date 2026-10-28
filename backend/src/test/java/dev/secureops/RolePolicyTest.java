package dev.secureops;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RolePolicyTest {
  @Test void viewerCannotPerformAdminOnlyAction() {
    assertFalse(RolePolicy.isAdmin(List.of(new SimpleGrantedAuthority("ROLE_VIEWER"))));
  }
  @Test void adminCanPerformAdminOnlyAction() {
    assertTrue(RolePolicy.isAdmin(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
  }
}

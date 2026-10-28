package dev.secureops;

import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public final class RolePolicy {
  private RolePolicy() {}
  public static boolean isAdmin(Collection<? extends GrantedAuthority> authorities) {
    return authorities.stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
  }
}

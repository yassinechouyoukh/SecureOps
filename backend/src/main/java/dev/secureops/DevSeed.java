package dev.secureops;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
@Profile({"dev", "preview"})
public class DevSeed {
  private final DetectionEngine detection = new DetectionEngine();

  @Bean ApplicationRunner seedDevelopmentData(JdbcTemplate db, PasswordEncoder encoder, ResourceLoader resources) {
    return args -> {
      String[][] users={{"admin@secureops.local","ADMIN"},{"analyst@secureops.local","ANALYST"},{"viewer@secureops.local","VIEWER"}};
      for (var user: users) {
        Integer count=db.queryForObject("select count(*) from app_user where email=?",Integer.class,user[0]);
        if(count==null||count==0) db.update("insert into app_user(email,password_hash,role) values (?,?,?)",user[0],encoder.encode("ChangeMe123!"),user[1]);
      }

      Integer eventCount=db.queryForObject("select count(*) from security_event",Integer.class);
      if(eventCount!=null&&eventCount>0) return;

      List<UUID> seededAlerts=new ArrayList<>();
      var resource=resources.getResource("classpath:demo-events.tsv");
      try (var reader=new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
        String line;
        while((line=reader.readLine())!=null) {
          if(line.isBlank()||line.startsWith("#")) continue;
          String[] fields=line.split("\\t",7);
          if(fields.length!=7) throw new IllegalStateException("Invalid demo event row: "+line);
          int minutesAgo=Integer.parseInt(fields[0]);
          UUID id=UUID.randomUUID();
          OffsetDateTime occurredAt=OffsetDateTime.now().minusMinutes(minutesAgo);
          db.update("insert into security_event(id,occurred_at,source_type,severity,category,source_ip,actor,description) values (?,?,?,?,?,?,?,?)",
              id,occurredAt,fields[1],fields[2],fields[3],fields[4],fields[5],fields[6]);

          Long failures=db.queryForObject("select count(*) from security_event where category='AUTHENTICATION' and source_ip=? and description ilike '%failed login%' and occurred_at > ?",Long.class,fields[4],occurredAt.minusMinutes(10));
          var match=detection.evaluate(fields[3],fields[6],failures==null?0:failures);
          if(match!=null) {
            UUID alertId=UUID.randomUUID();
            db.update("insert into alert(id,title,rule_key,severity,status,description,event_id,created_at,updated_at) values (?,?,?,?, 'NEW',?,?,?,?)",
                alertId,match.title(),match.ruleKey(),match.severity(),"Seeded synthetic event matched: "+match.title(),id,occurredAt,occurredAt);
            db.update("update security_event set detected=true where id=?",id);
            db.update("insert into audit_entry(action,actor,subject_id,details,occurred_at) values (?,?,?,?,?)",
                "DETECTION_ALERT_CREATED","system@secureops.local",id.toString(),match.ruleKey(),occurredAt);
            seededAlerts.add(alertId);
          }
        }
      } catch(IOException e) {
        throw new UncheckedIOException("Could not load bundled synthetic demo data",e);
      }

      if(!seededAlerts.isEmpty()) {
        UUID incidentId=UUID.randomUUID();
        OffsetDateTime now=OffsetDateTime.now();
        db.update("insert into incident(id,title,severity,status,assignee,created_at,updated_at,summary) values (?,?,?,'INVESTIGATING',?,?,?,?)",
            incidentId,"Suspicious authentication and privilege activity","HIGH","analyst@secureops.local",now,now,
            "Synthetic case linking the seeded login sequence and privilege-change alerts.");
        seededAlerts.forEach(alertId->db.update("insert into incident_alert(incident_id,alert_id) values (?,?)",incidentId,alertId));
        db.update("insert into audit_entry(action,actor,subject_id,details,occurred_at) values (?,?,?,?,?)",
            "INCIDENT_CREATED","analyst@secureops.local",incidentId.toString(),"Seeded synthetic investigation case",now);
      }
    };
  }
}

package dev.secureops;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.validation.annotation.Validated;
import java.time.OffsetDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/v1")
@Validated
public class ApiController {
  private final JdbcTemplate db;
  private final DetectionEngine detection = new DetectionEngine();
  public ApiController(JdbcTemplate db) { this.db = db; }
  public record EventInput(@NotBlank @Size(max=40) String sourceType, @NotBlank @Size(max=20) String severity,
      @NotBlank @Size(max=60) String category, @Size(max=45) String sourceIp, @Size(max=80) String actor,
      @NotBlank @Size(max=500) String description) {}
  @GetMapping("/auth/csrf") Map<String,String> csrf(org.springframework.security.web.csrf.CsrfToken token) { return Map.of("token", token.getToken()); }
  @GetMapping("/auth/me") Map<String,Object> me(Authentication a) { return Map.of("email", a.getName(), "roles", a.getAuthorities().stream().map(Object::toString).toList()); }
  @GetMapping("/dashboard") Map<String,Object> dashboard() {
    long events = value("select count(*) from security_event");
    long open = value("select count(*) from alert where status in ('NEW','ACKNOWLEDGED','INVESTIGATING')");
    long incidents = value("select count(*) from incident where status in ('OPEN','INVESTIGATING')");
    var latest = db.queryForList("select id as \"id\",title as \"title\",severity as \"severity\",status as \"status\",created_at as \"createdAt\" from alert order by created_at desc limit 6");
    var trend=db.queryForList("select date_trunc('hour',occurred_at) as \"time\",count(*) as \"events\" from security_event where occurred_at > ? group by date_trunc('hour',occurred_at) order by date_trunc('hour',occurred_at)",OffsetDateTime.now().minusHours(24));
    return Map.of("totalEvents",events,"openAlerts",open,"activeIncidents",incidents,"recentAlerts",latest,"eventTrend",trend);
  }
  @GetMapping("/events") List<Map<String,Object>> events(@RequestParam(defaultValue="100") int limit, @RequestParam(required=false) String keyword, @RequestParam(required=false) String severity, @RequestParam(required=false) String category) {
    int safeLimit = Math.max(1, Math.min(limit, 250));
    String q = keyword == null ? "" : keyword.trim();
    String safeSeverity=Set.of("LOW","MEDIUM","HIGH","CRITICAL").contains(Objects.toString(severity,"").toUpperCase())?severity.toUpperCase():"";
    String safeCategory=Set.of("AUTHENTICATION","PRIVILEGE_CHANGE","ADMIN_ACTION").contains(Objects.toString(category,"").toUpperCase())?category.toUpperCase():"";
    return db.queryForList("select id as \"id\",occurred_at as \"timestamp\",source_type as \"sourceType\",severity as \"severity\",category as \"category\",source_ip as \"sourceIp\",actor as \"actor\",description as \"description\",detected as \"detected\" from security_event where (description ilike ? or category ilike ?) and (?='' or severity=?) and (?='' or category=?) order by occurred_at desc limit ?", "%"+q+"%", "%"+q+"%", safeSeverity,safeSeverity,safeCategory,safeCategory,safeLimit);
  }
  @PostMapping("/events") @ResponseStatus(HttpStatus.CREATED)
  Map<String,Object> ingest(@Valid @RequestBody EventInput in, Authentication auth) {
    UUID id=UUID.randomUUID();
    db.update("insert into security_event(id,occurred_at,source_type,severity,category,source_ip,actor,description) values (?,now(),?,?,?,?,?,?)", id,in.sourceType(),in.severity().toUpperCase(),in.category(),in.sourceIp(),in.actor(),in.description());
    detect(id,in,auth.getName()); audit("EVENT_INGESTED",auth.getName(),id.toString(),in.category());
    return Map.of("id",id,"accepted",true);
  }
  @PostMapping("/events/demo") Map<String,Object> demo(Authentication auth) {
    String ip="198.51.100.42";
    for(int i=0;i<5;i++) { var in=new EventInput("IDENTITY","HIGH","AUTHENTICATION",ip,"demo-analyst","Synthetic failed login attempt"); ingest(in,auth); }
    var in=new EventInput("IDENTITY","HIGH","AUTHENTICATION",ip,"demo-analyst","Synthetic successful login following failures");
    ingest(in,auth);
    var admin=new EventInput("ADMIN","CRITICAL","PRIVILEGE_CHANGE","203.0.113.9","demo-admin","Synthetic privilege escalation event"); ingest(admin,auth);
    return Map.of("generated",7,"message","Synthetic demo scenario ingested");
  }
  @GetMapping("/alerts") List<Map<String,Object>> alerts() { return db.queryForList("select id as \"id\",title as \"title\",rule_key as \"ruleKey\",severity as \"severity\",status as \"status\",description as \"description\",event_id as \"eventId\",assignee as \"assignee\",created_at as \"createdAt\",updated_at as \"updatedAt\" from alert order by created_at desc limit 200"); }
  @PatchMapping("/alerts/{id}") Map<String,Object> changeAlert(@PathVariable UUID id,@RequestBody Map<String,String> body,Authentication auth) {
    String status=body.getOrDefault("status","").toUpperCase();
    if(!Set.of("NEW","ACKNOWLEDGED","INVESTIGATING","RESOLVED","FALSE_POSITIVE").contains(status)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Unsupported alert status");
    int n=db.update("update alert set status=?,updated_at=now() where id=?",status,id);
    if(n==0) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Alert not found");
    audit("ALERT_STATUS_CHANGED",auth.getName(),id.toString(),status); return Map.of("id",id,"status",status);
  }
  @GetMapping("/incidents") List<Map<String,Object>> incidents() { return db.queryForList("select id as \"id\",title as \"title\",severity as \"severity\",status as \"status\",assignee as \"assignee\",created_at as \"createdAt\",updated_at as \"updatedAt\",summary as \"summary\" from incident order by updated_at desc"); }
  @PostMapping("/incidents") @ResponseStatus(HttpStatus.CREATED) Map<String,Object> createIncident(@RequestBody Map<String,Object> body,Authentication auth) {
    String title=Objects.toString(body.get("title"),"").trim(); if(title.isEmpty()||title.length()>180) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Title is required (max 180 characters)");
    UUID id=UUID.randomUUID(); db.update("insert into incident(id,title,severity,status,assignee,created_at,updated_at,summary) values (?,?,'MEDIUM','OPEN',?,now(),now(),?)",id,title,auth.getName(),Objects.toString(body.get("summary"),""));
    audit("INCIDENT_CREATED",auth.getName(),id.toString(),title); return Map.of("id",id,"title",title,"status","OPEN");
  }
  @GetMapping("/audit") List<Map<String,Object>> audit() { return db.queryForList("select id as \"id\",action as \"action\",actor as \"actor\",subject_id as \"subjectId\",details as \"details\",occurred_at as \"occurredAt\" from audit_entry order by occurred_at desc limit 250"); }
  private long value(String sql) { Long n=db.queryForObject(sql,Long.class); return n==null?0:n; }
  private void detect(UUID id,EventInput in,String actor) {
    Long failures=db.queryForObject("select count(*) from security_event where category='AUTHENTICATION' and source_ip=? and description ilike '%failed login%' and occurred_at > ?",Long.class,in.sourceIp(),OffsetDateTime.now().minusMinutes(10));
    var match=detection.evaluate(in.category(),in.description(),failures==null?0:failures);
    if(match!=null) {
      db.update("insert into alert(id,title,rule_key,severity,status,description,event_id,created_at,updated_at) values (?,?,?,?, 'NEW',?,?,now(),now())",UUID.randomUUID(),match.title(),match.ruleKey(),match.severity(),"Synthetic rule matched: "+match.title(),id);
      db.update("update security_event set detected=true where id=?",id);
      audit("DETECTION_ALERT_CREATED",actor,id.toString(),match.ruleKey());
    }
  }
  private void audit(String action,String actor,String subject,String details) { db.update("insert into audit_entry(action,actor,subject_id,details,occurred_at) values (?,?,?,?,?)",action,actor,subject,details,OffsetDateTime.now()); }
}

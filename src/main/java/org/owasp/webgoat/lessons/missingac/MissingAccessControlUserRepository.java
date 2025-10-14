package org.owasp.webgoat.lessons.missingac;

import java.util.List;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;
import org.owasp.webgoat.container.users.WebGoatUser;

@Component
public class MissingAccessControlUserRepository {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final RowMapper<User> mapper =
            (rs, rowNum) ->
                    new User(rs.getString("username"), rs.getString("password"), rs.getBoolean("admin"));

    public MissingAccessControlUserRepository(LessonDataSource lessonDataSource) {
        this.jdbcTemplate = new NamedParameterJdbcTemplate(lessonDataSource);
    }

    public List<User> findAllUsers() {
        return jdbcTemplate.query("select username, password, admin from access_control_users", mapper);
    }

    public User findByUsername(String username) {
        var users =
                jdbcTemplate.query(
                        "select username, password, admin from access_control_users where username=:username",
                        new MapSqlParameterSource().addValue("username", username),
                        mapper);
        if (CollectionUtils.isEmpty(users)) {
            return null;
        }
        return users.get(0);
    }

    public User save(User user) {
        // Enforce access control: only allow users with admin privileges to set the admin flag
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean currentUserIsAdmin = false;
        if (authentication != null && authentication.getAuthorities() != null) {
            currentUserIsAdmin = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .anyMatch(authority -> WebGoatUser.ROLE_ADMIN.equals(authority));
        }
        boolean isAdminToSet = user.isAdmin();
        if (isAdminToSet && !currentUserIsAdmin) {
            // Non-admins cannot create or modify users with admin privileges
            throw new SecurityException("Unauthorized attempt to set admin privileges.");
        }
        jdbcTemplate.update(
                "INSERT INTO access_control_users(username, password, admin)"
                        + " VALUES(:username,:password,:admin)",
                new MapSqlParameterSource()
                        .addValue("username", user.getUsername())
                        .addValue("password", user.getPassword())
                        .addValue("admin", user.isAdmin()));
        return user;
    }
}

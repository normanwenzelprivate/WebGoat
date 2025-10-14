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

    /**
     * Finds a user by username, enforcing access control:
     * - Admins can retrieve any user
     * - Non-admins can only retrieve their own user record
     */
    public User findByUsername(String username) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        String currentUsername = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        // Only allow if admin or requesting own user
        if (!isAdmin && !currentUsername.equals(username)) {
            return null;
        }
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

/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.lessons;

import java.util.UUID;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Creates the lesson schema for a user. Each user owns their schema through a dedicated database
 * user without admin rights, lesson connections run as this database user see {@link
 * LessonConnectionInvocationHandler}. The lessons contain SQL injections on purpose, running them
 * as a user which only has privileges within its own schema keeps those injections inside the
 * lesson data of the user instead of exposing the schemas of other users or the container schema
 * holding the WebGoat accounts.
 */
@Service
@RequiredArgsConstructor
public class LessonSchemaService {

  private static final String DATABASE_USER_PREFIX = "lesson_";

  private final JdbcTemplate jdbcTemplate;
  private final Function<String, Flyway> flywayLessons;

  /** Name of the database user owning the lesson schema of the given WebGoat user. */
  public static String databaseUser(String username) {
    return DATABASE_USER_PREFIX + username;
  }

  public static String asIdentifier(String name) {
    return "\"" + name.replace("\"", "\"\"") + "\"";
  }

  public static String asLiteral(String value) {
    return "'" + value.replace("'", "''") + "'";
  }

  /** Creates the schema and its owner when the user does not own a lesson schema (yet). */
  public void createSchema(String username) {
    if (databaseUser(username).equals(schemaOwner(username))) {
      return;
    }
    if (schemaOwner(username) != null) {
      jdbcTemplate.execute("DROP SCHEMA %s CASCADE".formatted(asIdentifier(username)));
    }
    createDatabaseUser(username);
    jdbcTemplate.execute(
        "CREATE SCHEMA %s AUTHORIZATION %s"
            .formatted(asIdentifier(username), asIdentifier(databaseUser(username))));
    flywayLessons.apply(username).migrate();
  }

  /** Brings the lesson data of the user back to its initial state. */
  public void resetSchema(String username) {
    flywayLessons.apply(username).clean();
    createSchema(username); // Flyway might have dropped the schema itself while cleaning
    flywayLessons.apply(username).migrate();
  }

  private String schemaOwner(String username) {
    var owners =
        jdbcTemplate.queryForList(
            "SELECT schema_owner FROM information_schema.schemata WHERE schema_name = ?",
            String.class,
            username);
    return owners.isEmpty() ? null : owners.get(0);
  }

  private void createDatabaseUser(String username) {
    var databaseUser = databaseUser(username);
    var users =
        jdbcTemplate.queryForList(
            "SELECT user_name FROM information_schema.system_users WHERE user_name = ?",
            String.class,
            databaseUser);
    if (users.isEmpty()) {
      // nobody ever logs on with this user, lesson connections switch to it with SET SESSION
      // AUTHORIZATION, so the password is random and thrown away
      jdbcTemplate.execute(
          "CREATE USER %s PASSWORD %s"
              .formatted(asIdentifier(databaseUser), asLiteral(UUID.randomUUID().toString())));
    }
  }
}

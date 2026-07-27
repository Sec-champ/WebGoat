/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.lessons;

import static org.owasp.webgoat.container.lessons.LessonSchemaService.asIdentifier;
import static org.owasp.webgoat.container.lessons.LessonSchemaService.asLiteral;
import static org.owasp.webgoat.container.lessons.LessonSchemaService.databaseUser;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Handler which binds the connection to the currently bounded user. The connection continues as the
 * database user owning the schema of the user, which has no admin rights and no privileges outside
 * that schema. This way users are not seeing each other data, not even when they exploit one of the
 * SQL injections of the lessons, and we can reset data for just one particular user.
 */
public class LessonConnectionInvocationHandler implements InvocationHandler {

  private final Connection targetConnection;
  private boolean boundToUser = false;

  public LessonConnectionInvocationHandler(Connection targetConnection) {
    this.targetConnection = targetConnection;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!boundToUser
        && authentication != null
        && authentication.getPrincipal() instanceof WebGoatUser user) {
      try (var statement = targetConnection.createStatement()) {
        // dropping the admin rights of the session cannot be undone within the session
        statement.execute(
            "SET SESSION AUTHORIZATION " + asLiteral(databaseUser(user.getUsername())));
        statement.execute("SET SCHEMA " + asIdentifier(user.getUsername()));
      }
      boundToUser = true;
    }
    try {
      return method.invoke(targetConnection, args);
    } catch (InvocationTargetException e) {
      throw e.getTargetException();
    }
  }
}

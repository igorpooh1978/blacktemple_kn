Feature: Auth session routing
  UI must distinguish setup, login and authenticated state without treating
  public GET /api/v1/status as proof of a session.

  @BTKN-AUTH-001 @P0 @auth
  Scenario: UI startup distinguishes setup login and authenticated state
    Given GET /api/v1/auth/state
    When initialized is false
    Then the UI shows SETUP
    And when a password exists without a valid session the UI shows LOGIN
    And when btkn_session is valid the UI shows MAIN

  @BTKN-AUTH-002 @P0 @auth
  Scenario: Daemon restart invalidates RAM session
    Given a password is configured and the UI was authenticated
    When blacktempled restarts
    Then GET /api/v1/auth/state returns authenticated false
    And the UI returns to LOGIN not fake Main

  @BTKN-AUTH-003 @P0 @auth
  Scenario: 401 from a protected API returns UI to Login
    Given an authenticated UI
    When a protected API returns 401
    Then transient BlackKey and password fields are cleared
    And the UI switches to LOGIN
    And the message is Сессия истекла. Войдите снова.

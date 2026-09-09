Feature: Remote policy
  Remote policy cannot execute commands or override explicit user settings.

  @BTKN-POL-001 @P0 @policy
  Scenario: Remote policy cannot produce command execution
    Given a remote policy document
    When it is parsed
    Then no shell or exec fields are accepted

  @BTKN-POL-002 @P0 @policy
  Scenario: Local override beats remote policy
    Given a user override and a remote value
    When effective policy is computed
    Then the local override wins

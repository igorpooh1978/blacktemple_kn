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

  @BTKN-POL-003 @P0 @policy
  Scenario: Unknown x-* fields are ignored
    Given a document with unknown x- keys
    When parse runs
    Then known settings apply and unknown keys are ignored

  @BTKN-POL-004 @P0 @policy
  Scenario: Invalid known policy values are rejected
    Given a known key with an illegal value
    When parse runs
    Then ErrInvalidKnownKey is returned

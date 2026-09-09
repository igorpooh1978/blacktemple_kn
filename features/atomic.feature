Feature: Atomic storage
  Pointer replace must leave the previous file on failure.

  @BTKN-ATOM-001 @P0 @storage
  Scenario: Failed replace leaves the old file
    Given an existing atomic file
    When replace fails
    Then the previous contents remain

  @BTKN-ATOM-002 @P0 @storage
  Scenario: Successful atomic replace commits the new file
    Given an existing atomic file
    When replace succeeds
    Then the new contents are visible

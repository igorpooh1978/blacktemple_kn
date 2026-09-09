Feature: Atomic storage
  Pointer replace must leave the previous file on failure.

  @BTKN-ATOM-001 @P0 @storage
  Scenario: Failed replace leaves the old file
    Given an existing atomic file
    When replace fails
    Then the previous contents remain

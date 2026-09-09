Feature: Profiles and BlackKey
  P0 BlackKey lifecycle must stay fail-closed and secret-safe.

  @BTKN-PROF-001 @P0 @profiles
  Scenario: BlackKey state can select rotate and rollback
    Given stored keys for a profile
    When the manager selects rotates and rolls back
    Then no secret is logged and state remains consistent

  @BTKN-PROF-002 @P0 @profiles
  Scenario: Subscription parse rejects malformed input
    Given a malformed subscription body
    When parse runs
    Then the profile is not activated

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

  @BTKN-PROF-003 @P0 @profiles
  Scenario: Valid sanitized subscription URL import
    Given a fixture subscription at <BLACKKEY_SUBSCRIPTION_URL>
    When Import runs
    Then keys are stored without echoing the secret

  @BTKN-PROF-004 @P0 @profiles
  Scenario: Secret never appears in diagnostics
    Given an imported profile
    When logs and JSON diagnostics are written
    Then the BlackKey secret is absent

  @BTKN-PROF-005 @P0 @profiles
  Scenario: Profile create and select
    Given a valid share
    When Import and SelectCandidate run
    Then the profile is active and a candidate is selected

  @BTKN-PROF-006 @P0 @profiles
  Scenario: Profile delete is not in the current contract
    Given profiles.Service
    Then no Delete method is implemented in R6

  @BTKN-PROF-007 @P0 @profiles
  Scenario: Refresh failure preserves last-known-good keys
    Given an imported URL subscription
    When Refresh download fails
    Then previously stored keys remain

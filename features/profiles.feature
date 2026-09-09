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

  @BTKN-PROF-008 @P0 @profiles
  Scenario: Valid HTTPS BlackKey is fetched and parsed
    Given a fixture subscription at <BLACKKEY_SUBSCRIPTION_URL>
    When Import fetches HTTPS
    Then entries are parsed without logging the URL token

  @BTKN-PROF-009 @P0 @profiles
  Scenario: Failed subscription fetch does not create a partial profile
    Given a subscription URL that cannot be fetched
    When Import runs
    Then no profile is stored

  @BTKN-PROF-010 @P0 @profiles
  Scenario: Successful profile import survives daemon restart
    Given DataDir persistence
    When Import succeeds and a new Service opens the same DataDir
    Then the profile is restored without fetching the provider

  @BTKN-PROF-011 @P0 @profiles
  Scenario: Active profile survives daemon restart
    Given an imported active profile
    When a new Service opens the same DataDir
    Then ActiveID is restored

  @BTKN-PROF-012 @P0 @profiles
  Scenario: Parsed keys and servers survive restart without provider
    Given an imported subscription
    When the HTTP fixture is closed and Service is recreated
    Then keys and servers are still present

  @BTKN-PROF-013 @P0 @profiles
  Scenario: Active candidate survives daemon restart
    Given a selected candidate
    When Service is recreated on the same DataDir
    Then the candidate is restored

  @BTKN-PROF-014 @P0 @profiles
  Scenario: Persisted profile file is mode 0600
    Given DataDir persistence
    When Import writes profiles.json
    Then the file mode is 0600

  @BTKN-PROF-015 @P0 @profiles
  Scenario: Secret URL and key material never appear in profile API status errors or logs
    Given an imported profile
    When API status errors and logs are inspected
    Then the BlackKey secret and subscription token are absent

  @BTKN-PROF-016 @P0 @profiles
  Scenario: Failed persistence does not replace previous good state
    Given a durable good profiles.json
    When a later mutation cannot persist
    Then memory and disk keep the previous good state

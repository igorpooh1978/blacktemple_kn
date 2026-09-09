Feature: Provider key regeneration
  Regeneration uses the KeyChanger adapter, not subscription Refresh.
  The production provider HTTP contract is proven from APK evidence or blocked.

  @BTKN-KEYS-001 @P0 @keys
  Scenario: Regeneration uses the provider adapter not Refresh
    Given an imported profile
    When ChangeKey runs
    Then the KeyChanger adapter is called
    And subscription Refresh is not used

  @BTKN-KEYS-002 @P0 @keys
  Scenario: Successful regeneration replaces only the requested key
    Given a fake provider adapter returning a new share
    When ChangeKey succeeds
    Then only the requested key is replaced

  @BTKN-KEYS-003 @P0 @keys
  Scenario: Replacement share is parsed through the subscription parser
    Given a provider share URI
    When ChangeKey runs
    Then subscription.Parse classifies the replacement

  @BTKN-KEYS-004 @P0 @keys
  Scenario: New key is persisted atomically before becoming active
    Given DataDir persistence
    When ChangeKey succeeds
    Then profiles.json contains the new key before the next process reads it

  @BTKN-KEYS-005 @P0 @keys
  Scenario: Persistence failure leaves the old key active and durable
    Given a replace failure on profiles.json
    When ChangeKey persist fails
    Then the old key remains active in memory and on disk

  @BTKN-KEYS-006 @P0 @keys
  Scenario: Provider failure leaves the old key untouched
    Given KeyChanger returns an error
    When ChangeKey runs
    Then stored keys are unchanged

  @BTKN-KEYS-007 @P0 @keys
  Scenario: Invalid regenerated share leaves the old key untouched
    Given a provider response that is not a share
    When ChangeKey runs
    Then stored keys are unchanged

  @BTKN-KEYS-008 @P0 @keys
  Scenario: Unsupported regenerated protocol leaves the old key untouched
    Given a provider share that is not VLESS
    When ChangeKey runs
    Then stored keys are unchanged

  @BTKN-KEYS-009 @P0 @keys
  Scenario: New credential never appears in logs API status or errors
    Given a successful or failed ChangeKey
    When logs status errors and profile API are inspected
    Then the replacement secret is absent

  @BTKN-KEYS-010 @P0 @keys
  Scenario: Regenerated key survives blacktempled restart
    Given a successful ChangeKey
    When a new Service is opened on the same DataDir
    Then the replacement key is restored without fetching the provider

  @BTKN-KEYS-011 @P0 @keys
  Scenario: Active selection is preserved on the new key
    Given the replaced key was the active candidate
    When ChangeKey succeeds
    Then the active candidate uses the new key

  @BTKN-KEYS-012 @P0 @keys
  Scenario: Regeneration never touches netfilter or XKeen
    Given ChangeKey production sources
    Then they do not call iptables ip rule S05xkeen or netfilter Apply

  @BTKN-KEYS-013 @P0 @keys
  Scenario: Regeneration does not destroy a working SOCKS session before validation
    Given OUR SOCKS Xray is running
    When ChangeKey is requested
    Then the running Xray session is not stopped by the domain ChangeKey path

  @BTKN-KEYS-014 @P0 @keys
  Scenario: Failed replacement never breaks a working SOCKS connection
    Given OUR SOCKS Xray is running
    When ChangeKey fails
    Then the Xray process remains running

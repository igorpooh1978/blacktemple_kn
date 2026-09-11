Feature: Automatic BlackKey resolver
  Fresh BlackKey import must resolve runnable VLESS candidates without Android.

  @BTKN-R8-001 @P0 @profiles
  Scenario: Fresh BlackKey resolution returns runnable candidates
    Given a BlackKey whose subscription bootstrap is not a runnable Reality share
    When Import runs with an automatic resolver
    Then runnable VLESS WS TLS candidates are stored
    And resolutionState is resolved

  @BTKN-R8-002 @P0 @profiles
  Scenario: Raw bootstrap Reality entry never becomes runnable candidate
    Given a BlackKey bootstrap VLESS Reality payload with a non-X25519 pbk
    When Import and Resolve complete
    Then that bootstrap entry is not published as a runnable key or server

  @BTKN-R8-003 @P0 @xray
  Scenario: Resolved VLESS WS TLS candidates normalize correctly
    Given a resolver response containing VLESS WS TLS
    When candidates are normalized
    Then protocol network security and canonical UUID shape are preserved
    And Reality settings are absent

  @BTKN-R8-004 @P0 @profiles
  Scenario: Resolver failure preserves old resolved candidate set
    Given a profile with a stored resolved candidate set
    When Resolve fails
    Then the previous resolved keys and servers remain

  @BTKN-R8-005 @P0 @profiles
  Scenario: Resolver failure preserves LKG
    Given a profile with last-known-good after a successful connect
    When Resolve fails
    Then last-known-good is unchanged

  @BTKN-R8-006 @P0 @profiles
  Scenario: Resolver result persists atomically before publication
    Given a durable resolved profile
    When a later Resolve cannot persist
    Then memory and disk keep the previous resolved set

  @BTKN-R8-007 @P0 @connection
  Scenario: Restart restores resolved candidates without Android
    Given automatic resolution stored a resolved profile
    When a new Service opens the same DataDir
    Then resolved candidates are restored without provider refetch

  @BTKN-R8-008 @P0 @connection
  Scenario: Automatic resolved profile connects through SOCKS
    Given Import automatically resolved VLESS WS TLS candidates
    When connect runs
    Then Xray is connected on SOCKS 127.0.0.1:11080
    And capture and netfilter are not applied

  @BTKN-R8-009 @P0 @profiles
  Scenario: BlackKey and provider credentials never leak to API/log/errors
    Given automatic BlackKey resolution
    When status errors and diagnostics are inspected
    Then BlackKey UUID host SNI WS path and subscription URL values are absent

  @BTKN-R8-010 @P0 @connection
  Scenario: Resolver never invokes netfilter/XKeen
    Given resolver and profile sources
    Then they do not call ExecuteNetfilterReconcile S05xkeen iptables or ipset

  @BTKN-R8-011 @P0 @profiles
  Scenario: Provider signing credential is absent from tracked source
    Given tracked Go source
    Then no production BlackKey HMAC key literal is present

  @BTKN-R8-012 @P0 @profiles
  Scenario: Signed resolver rejects non-HTTPS URL
    Given a BlackKey URL with scheme http
    When Resolve runs
    Then the request is not sent
    And the resolver returns rejected

  @BTKN-R8-013 @P0 @profiles
  Scenario: Signed resolver rejects untrusted host
    Given a HTTPS BlackKey URL whose host is not on the local allowlist
    When Resolve runs
    Then signed provider headers are not sent
    And the resolver returns rejected

  @BTKN-R8-014 @P0 @profiles
  Scenario: Signed resolver rejects cross-host redirect
    Given an allowlisted HTTPS subscription that redirects to a foreign host
    When Resolve runs
    Then signature headers are not forwarded to the foreign host

  @BTKN-R8-015 @P0 @profiles
  Scenario: Missing local resolver credential preserves existing LKG
    Given a profile with last-known-good
    And the local HMAC secret file is absent
    When Resolve runs
    Then last-known-good is unchanged
    And Connect still uses the stored candidates

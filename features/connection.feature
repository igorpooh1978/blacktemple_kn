Feature: Connection
  Connecting must not leak secrets and must fail closed.

  @BTKN-CONN-001 @P0 @connection
  Scenario: Connection service start stop is fail-closed
    Given a fake Xray engine
    When connect and disconnect run
    Then secrets are not written to logs

  @BTKN-CONN-002 @P0 @connection
  Scenario: Connect and disconnect
    Given an imported profile
    When connect then disconnect run
    Then Xray starts and stops without leftover desired capture

  @BTKN-CONN-003 @P0 @connection
  Scenario: Restart-vpn replaces the Xray process
    Given a connected session
    When restart-vpn runs
    Then the Xray PID changes

  @BTKN-CONN-004 @P0 @connection
  Scenario: Invalid Xray config leaves the previous file
    Given a running generated config
    When validation fails
    Then the old config remains

  @BTKN-CONN-005 @P0 @connection
  Scenario: Xray start failure restores backup
    Given a previous config
    When Start fails
    Then the backup is restored

  @BTKN-CONN-006 @P0 @connection
  Scenario: Restart-manager and full-restart are unsupported
    Given the current R6 connection contract
    When restart-manager or full-restart is requested
    Then ErrUnsupportedInEnvironment is returned

  @BTKN-CONN-007 @P0 @connection
  Scenario: SOCKS-only connect generates exactly SOCKS inbound
    Given a VLESS profile
    When connect runs
    Then generated xray.json has socks-in on 127.0.0.1:11080
    And it has no redirect-in tproxy-in 11820 or transparentListen

  @BTKN-CONN-008 @P0 @connection
  Scenario: capture.enabled remains false during SOCKS connect
    Given capture.enabled is false
    When connect runs
    Then capture.enabled stays false

  @BTKN-CONN-009 @P0 @connection
  Scenario: SOCKS-only connect never calls netfilter-reconcile Apply
    Given the connection service sources
    When connect is implemented
    Then ExecuteNetfilterReconcile Apply is not called

  @BTKN-CONN-010 @P0 @connection
  Scenario: XKeen remains untouched while OUR SOCKS Xray starts and stops
    Given SOCKS connect and disconnect
    Then production sources do not stop S05xkeen or mutate ip rule

  @BTKN-CONN-011 @P0 @connection
  Scenario: SOCKS-only generated config is accepted by xray run -test
    Given a VLESS Reality or TLS candidate
    When SOCKS-only xray.json is generated
    Then xray run -test accepts it where the binary is available

  @BTKN-CONN-012 @P0 @connection
  Scenario: Failed connect classifies credential errors without values
    Given generate or xray run -test rejects a candidate
    When connect fails
    Then status connection is failed
    And errorClass is one of INVALID_VLESS_USER_ID INVALID_REALITY_PUBLIC_KEY INVALID_REALITY_SHORT_ID XRAY_CONFIG_REJECTED
    And the credential value is absent from status and errors

  @BTKN-CONN-013 @P0 @connection
  Scenario: Unresolved BlackKey profile fails with BLACKKEY_RESOLUTION_REQUIRED
    Given an imported BlackKey profile with only bootstrap Reality payload
    When connect runs
    Then it fails with BLACKKEY_RESOLUTION_REQUIRED
    And errorClass is not INVALID_REALITY_PUBLIC_KEY

  @BTKN-CONN-014 @P0 @connection
  Scenario: Candidate loop skips failed candidate and promotes first healthy candidate to LKG
    Given a resolved profile with two VLESS WS TLS candidates
    When connect run-test fails for the first candidate and the second is healthy
    Then Xray is connected on the second candidate
    And that candidate is last-known-good

  @BTKN-CONN-015 @P0 @connection
  Scenario: Restart restores resolved candidates and LKG without provider refetch
    Given a resolved profile with last-known-good after a successful connect
    When a new Service opens the same DataDir with the fixture closed
    Then resolved candidates and LKG are restored
    And connect does not fetch the provider

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

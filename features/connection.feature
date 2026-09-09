Feature: Connection
  Connecting must not leak secrets and must fail closed.

  @BTKN-CONN-001 @P0 @connection
  Scenario: Connection service start stop is fail-closed
    Given a fake Xray engine
    When connect and disconnect run
    Then secrets are not written to logs

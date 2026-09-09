Feature: Service lifecycle
  Supervisor and init must fail closed without live routing mutations.

  @BTKN-LIFE-001 @P0 @lifecycle
  Scenario: Supervisor transitions are explicit
    Given supervisor states
    When illegal transitions are requested
    Then they are rejected

  @BTKN-LIFE-002 @P0 @lifecycle
  Scenario: Reconcile without xray requests desired-absent
    Given missing or dead xray
    When platform Reconcile runs
    Then capture is not applied

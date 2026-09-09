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

  @BTKN-LIFE-003 @P0 @lifecycle
  Scenario: Network not ready keeps capture desired-absent
    Given platform network not ready
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-004 @P0 @lifecycle
  Scenario: Missing Xray keeps capture desired-absent
    Given no xray binary
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-005 @P0 @lifecycle
  Scenario: Network wait is bounded
    Given network never ready
    When WaitNetworkReady runs
    Then it times out without hanging

  @BTKN-LIFE-006 @P0 @lifecycle
  Scenario: Healthy running does not capture OUTPUT
    Given ready xray
    When Reconcile desired-present is evaluated
    Then OUTPUT is not captured and iptables is not called from this path

  @BTKN-LIFE-007 @P0 @lifecycle
  Scenario: Corrupt config keeps capture desired-absent
    Given a corrupt xray config
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-008 @P0 @lifecycle
  Scenario: Xray backoff keeps capture desired-absent
    Given xray restart backoff
    When Reconcile runs
    Then capture is not applied

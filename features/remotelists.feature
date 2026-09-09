Feature: Remote lists
  Downloads must block SSRF and keep last-known-good.

  @BTKN-LIST-001 @P0 @lists
  Scenario: Private IP SSRF is blocked
    Given a list URL that resolves to a private address
    When update runs
    Then the download is rejected

  @BTKN-LIST-002 @P0 @lists
  Scenario: Invalid content keeps last-known-good
    Given a cached valid list
    When the new body is invalid
    Then the cache remains

  @BTKN-LIST-003 @P0 @lists
  Scenario: HTTP 304 reuses the current list
    Given a cached list and matching ETag
    When update runs
    Then no new revision is activated

  @BTKN-LIST-004 @P0 @lists
  Scenario: Download failure preserves last-known-good
    Given a cached valid list
    When the download times out
    Then the cache remains

  @BTKN-LIST-005 @P0 @lists
  Scenario: Redirect target is revalidated
    Given a redirect to a blocked target
    When update runs
    Then the download is rejected and LKG remains

  @BTKN-LIST-006 @P0 @lists
  Scenario: GC does not activate orphan revisions
    Given an orphan revision file
    When recover runs
    Then it is not activated

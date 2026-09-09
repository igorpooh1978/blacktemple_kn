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

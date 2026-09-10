Feature: Xray configuration
  Generated configs must match golden files and never claim unsupported protocols.

  @BTKN-XRAY-001 @P0 @xray
  Scenario: SOCKS golden configs validate
    Given pinned Xray 26.7.28
    When generate writes SOCKS inbound configs
    Then they match golden testdata

  @BTKN-XRAY-002 @P0 @xray
  Scenario: Transparent TCP REDIRECT and UDP TPROXY inbounds are generated
    Given hybrid capture requirements
    When generate writes transparent config
    Then TCP followRedirect and UDP tproxy=tproxy are present on 11820

  @BTKN-XRAY-003 @P0 @xray
  Scenario: Transparent inbound is not a forward proxy
    Given a transparent golden config
    Then SOCKS remains on 11080 and 11820 is not SOCKS

  @BTKN-XRAY-004 @P0 @xray
  Scenario: Transparent port is 11820 and must not use XKeen 1181
    Given hybrid generate or StartTransparent
    Then the tunnel port is 11820
    And 1181 is rejected as reserved

  @BTKN-XRAY-005 @P0 @xray
  Scenario: Invalid transparent Xray config is rejected
    Given malformed or reserved-port options
    When generate runs
    Then the config is rejected

  @BTKN-XRAY-006 @P0 @xray
  Scenario: Xray secret redaction
    Given a generated config containing a UUID
    When Redact runs
    Then the secret is not present in diagnostics

  @BTKN-XRAY-007 @P0 @xray
  Scenario: Foreign XKeen Xray is never OUR Xray
    Given /opt/sbin/xray
    Then it is not accepted as /opt/blacktemple-kn/bin/xray
    And it must not own transparent port 11820

  @BTKN-XRAY-008 @P0 @xray
  Scenario: Detached OUR Xray keeps stdio off the parent CLI
    Given blacktempled xray-start with Detach
    Then child stdout and stderr are OS devnull files
    And they are not the parent io.Discard pipe

  @BTKN-XRAY-009 @P0 @xray
  Scenario: VLESS short user id is accepted per Xray mapping semantics
    Given a 4-byte UTF-8 VLESS user id
    When generate runs
    Then the config is emitted without converting the id to a UUID

  @BTKN-XRAY-010 @P0 @xray
  Scenario: Four-byte VLESS provider id reaches xray config validation
    Given id "test" and otherwise valid dummy TLS or Reality parameters
    When generate writes xray.json
    Then the JSON users.id is exactly that 4-byte value
    And xray run -test is attempted where the pinned binary is available

  @BTKN-XRAY-011 @P0 @xray
  Scenario: Canonical UUID VLESS id remains accepted unchanged
    Given a canonical RFC-style UUID
    When generate runs
    Then the users.id field is the same UUID

  @BTKN-XRAY-012 @P0 @xray
  Scenario: Empty VLESS user id is rejected
    Given an empty or whitespace-only VLESS id
    When generate runs
    Then the config is rejected

  @BTKN-XRAY-013 @P0 @xray
  Scenario: Arbitrary VLESS id longer than 30 UTF-8 bytes is rejected
    Given a 31-byte non-UUID VLESS id
    When generate runs
    Then the config is rejected
    And a 30-byte non-UUID id is accepted

  @BTKN-XRAY-014 @P0 @xray
  Scenario: Short VLESS id is never regenerated because it is not UUID-shaped
    Given id "test"
    When generate runs
    Then users.id is "test"
    And no new UUID is substituted
    And KeyChanger is not invoked

  @BTKN-XRAY-015 @P0 @xray
  Scenario: Secret VLESS user id never appears in logs status or errors
    Given a short or canonical VLESS id
    When generate fails or succeeds
    Then errors and status do not contain the id value

  @BTKN-XRAY-016 @P0 @xray
  Scenario: Reality public key is classified by X25519 structure
    Given a test X25519 public key encoded as Xray base64url
    When generate runs
    Then the key is accepted
    And a 5-character dummy is classified invalid without logging the value

  @BTKN-XRAY-017 @P0 @xray
  Scenario: Reality shortId empty is allowed and odd hex is rejected
    Given Reality security
    When shortId is empty
    Then generate accepts it
    And a structurally invalid shortId is classified without emitting the value

  @BTKN-XRAY-018 @P0 @xray
  Scenario: Resolved VLESS WS TLS generates valid SOCKS-only config
    Given a normalized VLESS WS TLS candidate
    When generate writes SOCKS-only xray.json
    Then the outbound is VLESS WS TLS
    And socks-in remains 127.0.0.1:11080
    And Reality settings are absent
    And xray run -test is attempted where the pinned binary is available

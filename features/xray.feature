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

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

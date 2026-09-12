Feature: Control panel main screen
  Authenticated LAN UI shows frozen OpenAPI status facts and redacted
  profiles. Connect remains the primary control. No Xray JSON editor.
  BlackKey secrets never appear in the list or status copy.

  @BTKN-UI-001 @P0 @ui
  Scenario: Main screen shows country and latency from status
    Given GET /api/v1/status includes country and latencyMs
    When the authenticated UI loads MAIN
    Then country and ping from the payload are shown
    And empty country or null latencyMs is an em dash
    And no invented country name is used

  @BTKN-UI-002 @P0 @ui
  Scenario: Main screen lists redacted profiles
    Given GET /api/v1/profiles returns id name and status
    When the authenticated UI loads MAIN
    Then profile names and statuses are shown
    And blackKey is absent from the list JSON and the DOM

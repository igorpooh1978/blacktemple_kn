Feature: Geodata
  GeoIP/GeoSite updates must not activate corrupt candidates.

  @BTKN-GEO-001 @P0 @geodata
  Scenario: Failed validator leaves working geodata untouched
    Given an active geodata file
    When the candidate fails validation
    Then the active file is unchanged

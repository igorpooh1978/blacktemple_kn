Feature: Geodata
  GeoIP/GeoSite updates must not activate corrupt candidates.

  @BTKN-GEO-001 @P0 @geodata
  Scenario: Failed validator leaves working geodata untouched
    Given an active geodata file
    When the candidate fails validation
    Then the active file is unchanged

  @BTKN-GEO-002 @P0 @geodata
  Scenario: Checksum fail preserves active geodata
    Given an active pair
    When the candidate checksum mismatches
    Then active remains the previous files

  @BTKN-GEO-003 @P0 @geodata
  Scenario: Pointer or metadata failure preserves active
    Given an active pair
    When state pointer write fails
    Then active remains unchanged

  @BTKN-GEO-004 @P0 @geodata
  Scenario: Rollback restores the previous pointer
    Given active and previous revisions
    When Rollback runs
    Then previous becomes active

  @BTKN-GEO-005 @P0 @geodata
  Scenario: GC does not delete active or previous
    Given a GC failure
    Then active remains usable

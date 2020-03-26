See also http://pvp.haskell.org/faq

# Revision history for `resolv`

## 0.1.2.0

* Add new high-level API functions `queryPTR`, `arpaIPv4`, and
  `arpaIPv6` for performing reverse address lookups.

## 0.1.1.3

* GHC 8.8 / base-4.13 only compat hotfix release; the next release will support
  older GHC/base versions again

## 0.1.1.2

* Clarify/relax licensing terms

## 0.1.1.1

* Improve Autoconf script

## 0.1.1.0

* Use Autoconf to detect which library (if any) to link for `res_query(3)`
* Use reentrant `res_nquery(3)` API if available and signal via new `resIsReentrant :: Bool` constant
* Expose `DnsException` and `QR`

## 0.1.0.0

* First version. Released on an unsuspecting world.

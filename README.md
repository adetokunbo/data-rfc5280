# data-rfc5280

[![GitHub CI](https://github.com/adetokunbo/data-rfc5280/actions/workflows/cabal.yml/badge.svg)](https://github.com/adetokunbo/data-rfc5280/actions)
[![Stackage Nightly](http://stackage.org/package/data-rfc5280/badge/nightly)](http://stackage.org/nightly/package/data-rfc5280)
[![Hackage][hackage-badge]][hackage]
[![BSD3](https://img.shields.io/badge/license-BSD3-green.svg?dummy)](https://github.com/adetokunbo/data-rfc5280/blob/main/LICENSE)

`data-rfc5280` provides Haskell types that represent the standard X.509v3
certificate extensions defined in [RFC 5280].

Extensions covered include `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`,
`SubjectAltName`, `IssuerAltName`, `AuthorityKeyIdentifier`,
`SubjectKeyIdentifier`, `CertificatePolicies`, `PolicyMappings`,
`NameConstraints`, `CRLDistributionPoints`, `AuthorityInfoAccess`, and
`InhibitAnyPolicy`.

Each extension value can be serialised to OpenSSL configuration format as a
`ByteString`, suitable for use with OpenSSL config files.

## Example

```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Char8 as BC8
import Data.Rfc5280

-- Render a critical nameConstraints extension restricting issuance to
-- .example.com while excluding .evil.example.com.
example :: IO ()
example = do
  permitted <- assertRight $ mkDnsConstraint ".example.com"
  excluded <- assertRight $ mkDnsConstraint ".evil.example.com"
  let nc = mkNameConstraints (Permitted (DNS permitted)) [Excluded (DNS excluded)]
      ext = Extension {extCritical = True, extValue = nc}
  BC8.putStrLn $ renderConfig ext
  -- critical,permitted;DNS:.example.com,excluded;DNS:.evil.example.com
```

[RFC 5280]:           https://datatracker.ietf.org/doc/html/rfc5280
[hackage-badge]: <https://img.shields.io/hackage/v/data-rfc5280.svg>
[hackage]:            <https://hackage.haskell.org/package/data-rfc5280>

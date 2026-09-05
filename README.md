# data-rfc5280

[![GitHub CI](https://github.com/adetokunbo/data-rfc5280/actions/workflows/cabal.yml/badge.svg)](https://github.com/adetokunbo/data-rfc5280/actions)
[![Stackage Nightly](http://stackage.org/package/data-rfc5280/badge/nightly)](http://stackage.org/nightly/package/data-rfc5280)
[![Hackage][hackage-badge]][hackage]
[![Hackage Dependencies][hackage-deps-badge]][hackage-deps]
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

-- Render the basicConstraints extension for a CA with a path length of 2.
example :: IO ()
example = case mkBasicConstraints True (Just 2) of
  Left err -> print err
  Right bc -> do
    let ext = Extension {extCritical = True, extValue = bc}
    BC8.putStrLn $ renderConfig ext
    -- critical,CA:TRUE,pathLen2
```

[RFC 5280]:           https://datatracker.ietf.org/doc/html/rfc5280
[hackage-deps-badge]: <https://img.shields.io/hackage-deps/v/data-rfc5280.svg>
[hackage-deps]:       <http://packdeps.haskellers.com/feed?needle=data-rfc5280>
[hackage-badge]:      <https://img.shields.io/hackage/v/data-rfc5280.svg>
[hackage]:            <https://hackage.haskell.org/package/data-rfc5280>

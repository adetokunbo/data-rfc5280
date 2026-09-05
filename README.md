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

## Example: TLS end-entity certificate

```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Char8 as BC8
import Data.Rfc5280
import qualified Net.IP as IP

-- Build and render the core extensions for a TLS end-entity certificate.
example2 :: IO ()
example2 = do
  bc  <- assertRight $ mkBasicConstraints False Nothing
  dn1 <- assertRight $ mkDnsName "example.com"
  dn2 <- assertRight $ mkDnsName "www.example.com"
  ip  <- assertJust "invalid IP" $ IP.decode "192.0.2.1"
  let ku  = fromList (DigitalSignature :| [KeyEncipherment]) :: KeyUsage
      eku = fromList (ServerAuth :| [ClientAuth]) :: ExtKeyUsage
      san = mkSubjectAltName (DNS dn1) [DNS dn2, IPAddr ip]
      aki = mkAuthorityKeyIdentifier True False False False
  BC8.putStrLn $ renderConfig $ Extension {extCritical = True,  extValue = bc}
  -- critical,CA:FALSE
  BC8.putStrLn $ renderConfig $ Extension {extCritical = True,  extValue = ku}
  -- critical,digitalSignature,keyEncipherment
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = eku}
  -- serverAuth,clientAuth
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = san}
  -- DNS:example.com,DNS:www.example.com,IP:192.0.2.1
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = HashMethod}
  -- hash
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = aki}
  -- keyid
```

## Example: CA infrastructure extensions

```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Char8 as BC8
import Data.Rfc5280
import Data.Rfc5280.AuthorityInfoAccess (AccessDescription (..), mkAuthorityInfoAccess)
import Text.URI (mkURI)

-- Build and render CA-infrastructure extensions: certificate policies,
-- authority info access, CRL distribution points, policy mappings, and
-- inhibitAnyPolicy.
example3 :: IO ()
example3 = do
  ocspUri       <- mkURI "https://ocsp.example.com"
  caUri         <- mkURI "https://ca.example.com/ca.crt"
  crlUri        <- mkURI "https://crl.example.com/root.crl"
  anyPolicy     <- assertRight $ mkOID 2 [5, 29, 32, 0]
  customPolicy  <- assertRight $ mkOID 1 [3, 6, 1, 4, 1, 99999, 1]
  issuerDomain  <- assertRight $ mkOID 2 [5, 29, 32, 1]
  subjectDomain <- assertRight $ mkOID 2 [5, 29, 32, 2]
  inhibit       <- assertRight $ mkInhibitAnyPolicy 0
  let cp  = mkCertificatePolicies anyPolicy [customPolicy]
      aia = mkAuthorityInfoAccess
              (OCSP (URIName ocspUri))
              [CAIssuers (URIName caUri)]
      crl = mkCRLDistributionPoints
              (mkDistributionPoint (URIName crlUri))
              []
      pm  = mkPolicyMappings (mkPolicyMapping issuerDomain subjectDomain) []
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = cp}
  -- 2.5.29.32.0,1.3.6.1.4.1.99999.1
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = aia}
  -- OCSP;URI:https://ocsp.example.com,caIssuers;URI:https://ca.example.com/ca.crt
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = crl}
  -- URI:https://crl.example.com/root.crl
  BC8.putStrLn $ renderConfig $ Extension {extCritical = False, extValue = pm}
  -- 2.5.29.32.1:2.5.29.32.2
  BC8.putStrLn $ renderConfig $ Extension {extCritical = True,  extValue = inhibit}
  -- critical,0
```

[RFC 5280]:           https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
[hackage-badge]: <https://img.shields.io/hackage/v/data-rfc5280.svg>
[hackage]:            <https://hackage.haskell.org/package/data-rfc5280>

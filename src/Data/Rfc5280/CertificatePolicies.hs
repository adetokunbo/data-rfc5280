{- |
Module      : Data.Rfc5280.CertificatePolicies
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'CertificatePolicies' extension type and its smart constructor.
-}
module Data.Rfc5280.CertificatePolicies
  ( CertificatePolicies (..)
  , mkCertificatePolicies
  )
where

import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280.HasOID (HasOID (..))
import Data.Rfc5280.Internal (OID, RenderConfig (..), intersperseCommas, oidBuilder)


{- | Represents @CertificatePolicies@ (RFC 5280 §4.2.1.4).

Only the policy OIDs are modelled. @PolicyQualifierInfo@ entries (CPS URIs,
user notices) are not yet supported.
-}
newtype CertificatePolicies = CertificatePolicies (NonEmpty OID)
  deriving (Eq, Show)


-- | Construct @CertificatePolicies@ from a non-empty sequence of OIDs.
mkCertificatePolicies :: OID -> [OID] -> CertificatePolicies
mkCertificatePolicies x xs = CertificatePolicies $ x :| xs


instance HasOID CertificatePolicies where
  extensionOID _ = 2 :| [5, 29, 32]


instance RenderConfig CertificatePolicies where
  renderBuilder (CertificatePolicies xs) = intersperseCommas $ fmap oidBuilder xs

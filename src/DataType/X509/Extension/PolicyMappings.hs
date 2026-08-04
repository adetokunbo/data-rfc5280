{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.PolicyMappings
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'PolicyMappings', representing the X.509 Policy Mappings extension
(RFC 5280 §4.2.1.5).
-}
module DataType.X509.Extension.PolicyMappings
  ( PolicyMappings (..)
  , mkPolicyMappings
  , PolicyMapping (..)
  , mkPolicyMapping
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.HasOID (HasOID (..))
import DataType.X509.Extension.Internal (OID, intersperseCommas, oidBuilder)


{- | A single policy mapping, pairing an issuer domain policy OID with a
subject domain policy OID.
-}
data PolicyMapping = PolicyMapping
  { pmIssuerDomainPolicy  :: !OID  -- ^ The issuer's policy OID.
  , pmSubjectDomainPolicy :: !OID  -- ^ The subject's corresponding policy OID.
  }
  deriving (Eq, Show)


{- | Represents the PolicyMappings extension (RFC 5280 §4.2.1.5).

Contains one or more 'PolicyMapping' pairs. Use 'mkPolicyMappings' to
construct a value.
-}
newtype PolicyMappings = PolicyMappings (NonEmpty PolicyMapping)
  deriving (Eq, Show)


-- | Construct a 'PolicyMapping' from an issuer domain policy OID and a subject domain policy OID.
mkPolicyMapping :: OID -> OID -> PolicyMapping
mkPolicyMapping = PolicyMapping


-- | Construct a 'PolicyMappings' from one or more 'PolicyMapping' values.
mkPolicyMappings :: PolicyMapping -> [PolicyMapping] -> PolicyMappings
mkPolicyMappings x xs = PolicyMappings (x :| xs)


instance HasOID PolicyMappings where
  extensionOID _ = 2 :| [5, 29, 33]


instance ToBuilder PolicyMapping Builder where
  toBuilder pm = oidBuilder (pmIssuerDomainPolicy pm) <> ":" <> oidBuilder (pmSubjectDomainPolicy pm)


instance ToBuilder PolicyMappings Builder where
  toBuilder (PolicyMappings ms) = intersperseCommas (fmap toBuilder ms)

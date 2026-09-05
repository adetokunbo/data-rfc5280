{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.Rfc5280.AuthorityInfoAccess
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'AuthorityInfoAccess', representing the X.509 Authority Information
Access extension (RFC 5280 §4.2.2.1).
-}
module Data.Rfc5280.AuthorityInfoAccess
  ( AuthorityInfoAccess (..)
  , mkAuthorityInfoAccess
  , AccessDescription (..)
  )
where

import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280.GeneralName (GeneralName)
import Data.Rfc5280.HasOID (HasOID (..))
import Data.Rfc5280.Internal (RenderConfig (..), intersperseCommas)


{- | A single access point within an 'AuthorityInfoAccess' extension.

The 'GeneralName' location is almost always a 'URIName' in practice, but
any variant is permitted by RFC 5280.
-}
data AccessDescription
  = -- | An OCSP responder location. Rendered as @OCSP;\<location\>@.
    OCSP !GeneralName
  | -- | A CA issuers location. Rendered as @caIssuers;\<location\>@.
    CAIssuers !GeneralName
  deriving (Eq, Show)


{- | Represents the AuthorityInfoAccess extension (RFC 5280 §4.2.2.1).

Contains one or more 'AccessDescription' values. Use 'mkAuthorityInfoAccess'
to construct a value.
-}
newtype AuthorityInfoAccess = AuthorityInfoAccess (NonEmpty AccessDescription)
  deriving (Eq, Show)


-- | Construct an 'AuthorityInfoAccess' from one or more 'AccessDescription' values.
mkAuthorityInfoAccess :: AccessDescription -> [AccessDescription] -> AuthorityInfoAccess
mkAuthorityInfoAccess x xs = AuthorityInfoAccess (x :| xs)


instance HasOID AuthorityInfoAccess where
  extensionOID _ = 1 :| [3, 6, 1, 5, 5, 7, 1, 1]


instance RenderConfig AccessDescription where
  renderBuilder (OCSP loc) = "OCSP;" <> renderBuilder loc
  renderBuilder (CAIssuers loc) = "caIssuers;" <> renderBuilder loc


instance RenderConfig AuthorityInfoAccess where
  renderBuilder (AuthorityInfoAccess xs) = intersperseCommas (fmap renderBuilder xs)

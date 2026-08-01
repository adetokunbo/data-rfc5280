{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.AuthorityInfoAccess
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'AuthorityInfoAccess', representing the X.509 Authority Information
Access extension (RFC 5280 §4.2.2.1).
-}
module DataType.X509.Extension.AuthorityInfoAccess
  ( AuthorityInfoAccess (..)
  , mkAuthorityInfoAccess
  , AccessDescription (..)
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.GeneralName (GeneralName)
import DataType.X509.Extension.Internal (intersperseCommas)


{- | A single access point within an 'AuthorityInfoAccess' extension.

The 'GeneralName' location is almost always a 'URIName' in practice, but
any variant is permitted by RFC 5280.
-}
data AccessDescription
  = OCSP GeneralName
  -- ^ An OCSP responder location. Rendered as @OCSP;\<location\>@.
  | CAIssuers GeneralName
  -- ^ A CA issuers location. Rendered as @caIssuers;\<location\>@.
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


instance ToBuilder AccessDescription Builder where
  toBuilder (OCSP loc)      = "OCSP;"      <> toBuilder loc
  toBuilder (CAIssuers loc) = "caIssuers;" <> toBuilder loc


instance ToBuilder AuthorityInfoAccess Builder where
  toBuilder (AuthorityInfoAccess xs) = intersperseCommas (fmap toBuilder xs)

{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : DataType.X509.Extension.IssuerAltName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'IssuerAltName', representing the X.509 Issuer Alternative Name
extension (RFC 5280 §4.2.1.7).
-}
module DataType.X509.Extension.IssuerAltName
  ( IssuerAltName (..)
  , mkIssuerAltName
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.GeneralName (GeneralName)
import DataType.X509.Extension.HasOID (HasOID (..))
import DataType.X509.Extension.Internal (intersperseCommas)


{- | Represents the IssuerAltName extension (RFC 5280 §4.2.1.7).

Contains one or more 'GeneralName' values identifying the issuer. Use
'mkIssuerAltName' to construct a value.
-}
newtype IssuerAltName = IssuerAltName (NonEmpty GeneralName)
  deriving (Eq, Show)


-- | Construct an 'IssuerAltName' from one or more 'GeneralName' values.
mkIssuerAltName :: GeneralName -> [GeneralName] -> IssuerAltName
mkIssuerAltName x xs = IssuerAltName (x :| xs)


instance HasOID IssuerAltName where
  extensionOID _ = 2 :| [5, 29, 18]


instance ToBuilder IssuerAltName Builder where
  toBuilder (IssuerAltName names) = intersperseCommas (fmap toBuilder names)

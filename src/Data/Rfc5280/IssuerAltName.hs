{- |
Module      : Data.Rfc5280.IssuerAltName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'IssuerAltName', representing the X.509 Issuer Alternative Name
extension (RFC 5280 §4.2.1.7).
-}
module Data.Rfc5280.IssuerAltName
  ( IssuerAltName (..)
  , mkIssuerAltName
  )
where

import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280.GeneralName (GeneralName)
import Data.Rfc5280.HasOID (HasOID (..))
import Data.Rfc5280.Internal (RenderConfig (..), intersperseCommas)


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


instance RenderConfig IssuerAltName where
  renderBuilder (IssuerAltName names) = intersperseCommas (fmap renderBuilder names)

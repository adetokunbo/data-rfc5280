{- |
Module      : Data.Rfc5280.SubjectAltName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'SubjectAltName', representing the X.509 Subject Alternative Name
extension (RFC 5280 §4.2.1.6).
-}
module Data.Rfc5280.SubjectAltName
  ( SubjectAltName (..)
  , mkSubjectAltName
  )
where

import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280.GeneralName (GeneralName)
import Data.Rfc5280.HasOID (HasOID (..))
import Data.Rfc5280.Internal (RenderConfig (..), intersperseCommas)


{- | Represents the SubjectAltName extension (RFC 5280 §4.2.1.6).

Contains one or more 'GeneralName' values identifying the subject. Use
'mkSubjectAltName' to construct a value.
-}
newtype SubjectAltName = SubjectAltName (NonEmpty GeneralName)
  deriving (Eq, Show)


-- | Construct a 'SubjectAltName' from one or more 'GeneralName' values.
mkSubjectAltName :: GeneralName -> [GeneralName] -> SubjectAltName
mkSubjectAltName x xs = SubjectAltName (x :| xs)


instance HasOID SubjectAltName where
  extensionOID _ = 2 :| [5, 29, 17]


instance RenderConfig SubjectAltName where
  renderBuilder (SubjectAltName names) = intersperseCommas (fmap renderBuilder names)

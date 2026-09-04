{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : Data.X509.XT.SubjectAltName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'SubjectAltName', representing the X.509 Subject Alternative Name
extension (RFC 5280 §4.2.1.6).
-}
module Data.X509.XT.SubjectAltName
  ( SubjectAltName (..)
  , mkSubjectAltName
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import Data.X509.XT.GeneralName (GeneralName)
import Data.X509.XT.HasOID (HasOID (..))
import Data.X509.XT.Internal (intersperseCommas)


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


instance ToBuilder SubjectAltName Builder where
  toBuilder (SubjectAltName names) = intersperseCommas (fmap toBuilder names)



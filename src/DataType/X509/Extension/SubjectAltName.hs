{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : DataType.X509.Extension.SubjectAltName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'SubjectAltName', representing the X.509 Subject Alternative Name
extension (RFC 5280 §4.2.1.6).
-}
module DataType.X509.Extension.SubjectAltName
  ( SubjectAltName (..)
  , mkSubjectAltName
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.GeneralName (GeneralName)
import DataType.X509.Extension.Internal (intersperseCommas)


{- | Represents the SubjectAltName extension (RFC 5280 §4.2.1.6).

Contains one or more 'GeneralName' values identifying the subject. Use
'mkSubjectAltName' to construct a value.
-}
newtype SubjectAltName = SubjectAltName (NonEmpty GeneralName)
  deriving (Eq, Show)


-- | Construct a 'SubjectAltName' from one or more 'GeneralName' values.
mkSubjectAltName :: GeneralName -> [GeneralName] -> SubjectAltName
mkSubjectAltName x xs = SubjectAltName (x :| xs)


instance ToBuilder SubjectAltName Builder where
  toBuilder (SubjectAltName names) = intersperseCommas (fmap toBuilder names)



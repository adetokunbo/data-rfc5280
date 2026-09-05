{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.Rfc5280.SubjectKeyIdentifier
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'SubjectKeyIdentifier' extension type.
-}
module Data.Rfc5280.SubjectKeyIdentifier
  ( SubjectKeyIdentifier (..)
  )
where

import Data.ByteString (ByteString)
import Data.ByteString.Builder (byteString)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280.HasOID (HasOID (..))
import Data.Rfc5280.Internal (RenderConfig (..))


-- | Represents a SubjectKeyIdentifier value (RFC 5280 §4.2.1.2).
data SubjectKeyIdentifier
  = {- | A raw key identifier. The caller supplies the bytes directly —
    typically the SHA-1 hash of the BIT STRING value of the
    subjectPublicKey field.
    -}
    Raw !ByteString
  | {- | Use the default hash method: the 160-bit SHA-1 hash of the
    subjectPublicKey BIT STRING, as defined in RFC 5280 §4.2.1.2.
    -}
    HashMethod
  deriving (Eq, Show)


instance HasOID SubjectKeyIdentifier where
  extensionOID _ = 2 :| [5, 29, 14]


instance RenderConfig SubjectKeyIdentifier where
  renderBuilder (Raw x) = byteString x
  renderBuilder HashMethod = "hash"

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.SubjectKeyIdentifier
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'SubjectKeyIdentifier' extension type.
-}
module DataType.X509.Extension.SubjectKeyIdentifier
  ( SubjectKeyIdentifier (..)
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder, byteString)


{- | Represents a SubjectKeyIdentifier value (RFC 5280 §4.2.1.2).
-}
data SubjectKeyIdentifier
  = Raw ByteString
  -- ^ A raw key identifier. The caller supplies the bytes directly —
  -- typically the SHA-1 hash of the BIT STRING value of the
  -- subjectPublicKey field.
  | HashMethod
  -- ^ Use the default hash method: the 160-bit SHA-1 hash of the
  -- subjectPublicKey BIT STRING, as defined in RFC 5280 §4.2.1.2.
  deriving (Eq, Show)


instance ToBuilder SubjectKeyIdentifier Builder where
  toBuilder (Raw x)    = byteString x
  toBuilder HashMethod = "hash"

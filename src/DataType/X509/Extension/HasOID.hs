{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.HasOID
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'HasOID' typeclass for associating extension types with their
RFC 5280 OIDs, and the 'Extension' wrapper for pairing a value with its
criticality flag.
-}
module DataType.X509.Extension.HasOID
  ( HasOID (..)
  , Extension (..)
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.Proxy (Proxy)
import DataType.X509.Extension.Internal (OID)


-- | Associates an extension type with its RFC 5280 OID.
class HasOID a where
  -- | Return the OID assigned to extension type @a@ by RFC 5280.
  extensionOID :: Proxy a -> OID


{- | Pairs an extension value with its RFC 5280 criticality flag.

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
-}
data Extension a = Extension
  { extCritical :: !Bool
  -- ^ 'True' if the extension is marked critical.
  , extValue    :: !a
  -- ^ The extension value.
  }
  deriving (Eq, Show)


{- | Renders as @\"critical,\<value\>\"@ when 'extCritical' is 'True',
or just @\<value\>@ otherwise.
-}
instance (ToBuilder a Builder) => ToBuilder (Extension a) Builder where
  toBuilder (Extension critical val)
    | critical  = "critical," <> toBuilder val
    | otherwise = toBuilder val

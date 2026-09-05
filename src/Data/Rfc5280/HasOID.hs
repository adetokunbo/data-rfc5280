{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.Rfc5280.HasOID
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'HasOID' typeclass for associating extension types with their
RFC 5280 OIDs, and the 'Extension' wrapper for pairing a value with its
criticality flag.
-}
module Data.Rfc5280.HasOID
  ( HasOID (..)
  , Extension (..)
  )
where

import Data.Proxy (Proxy)
import Data.Rfc5280.Internal (OID, RenderConfig (..))


-- | Associates an extension type with its RFC 5280 OID.
class HasOID a where
  -- | Return the OID assigned to extension type @a@ by RFC 5280.
  extensionOID :: Proxy a -> OID


{- | Pairs an extension value with its RFC 5280 criticality flag.

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9 RFC 5280 §4.1.2.9>.
-}
data Extension a = Extension
  { extCritical :: !Bool
  -- ^ 'True' if the extension is marked critical.
  , extValue :: !a
  -- ^ The extension value.
  }
  deriving (Eq, Show)


{- | Renders as @\"critical,\<value\>\"@ when 'extCritical' is 'True',
or just @\<value\>@ otherwise.
-}
instance (RenderConfig a) => RenderConfig (Extension a) where
  renderBuilder (Extension critical val)
    | critical = "critical," <> renderBuilder val
    | otherwise = renderBuilder val

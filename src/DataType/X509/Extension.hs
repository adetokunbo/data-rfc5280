{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension
Copyright   : (c) 2023 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides functions and/or data types that support Top Sample goals
-}
module DataType.X509.Extension
  ( -- * Extension types
    BasicConstraints (..)

    -- * Print types as @ByteString@
  , asByteString
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (intDec, toLazyByteString)


{- | Represents the basic constraints extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
-}
data BasicConstraints
  = BasicConstraints
  { bcIsCA :: !Bool
  -- ^ is the subject of the certificate a certificate authority
  , bcPathLength :: !(Maybe Int)
  -- ^ the maximum number of non-self-issued intermediate certificates
  -- ^ that may follow this certificate if it is a CA certificate
  }
  deriving (Eq, Show)


asByteString :: BasicConstraints -> ByteString
asByteString BasicConstraints{bcIsCA, bcPathLength} =
  let bcPrefix = "CA:"
      bcSuffix = if bcIsCA then "TRUE" else "FALSE"
      withPathLen x = ",pathLen" <> intDec x
      pathLen = maybe "" withPathLen bcPathLength
   in BS.toStrict $ toLazyByteString (bcPrefix <> bcSuffix <> pathLen)

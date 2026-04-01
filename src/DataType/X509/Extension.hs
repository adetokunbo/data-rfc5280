{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}

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
  , KeyUsageBit (..)
  , KeyUsage

    -- * Print types as @ByteString@
  , asByteString

    -- * re-export
  , fromList
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder, intDec, toLazyByteString)
import Data.List (foldl')
import Data.Set (Set, fromList, toList)


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


instance ToBuilder BasicConstraints Builder where
  toBuilder bc =
    let BasicConstraints{bcIsCA, bcPathLength} = bc
        bcPrefix = "CA:"
        bcSuffix = if bcIsCA then "TRUE" else "FALSE"
        withPathLen x = ",pathLen" <> intDec x
        pathLen = maybe "" withPathLen bcPathLength
     in (bcPrefix <> bcSuffix <> pathLen)


asByteString :: (ToBuilder a Builder) => a -> ByteString
asByteString = BS.toStrict . toLazyByteString . toBuilder


{- | Represents the bits that can set for @KeyUsage@

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
-}
data KeyUsageBit
  = DigitalSignature
  | NonRepudiation
  | KeyEncipherment
  | DataEncipherment
  | KeyAgreement
  | KeyCertSign
  | CRLSign
  | EncipherOnly
  | DecipherOnly
  deriving (Eq, Show, Ord, Enum)


instance ToBuilder KeyUsageBit Builder where
  toBuilder DigitalSignature = "digitalSignature"
  toBuilder NonRepudiation = "nonRepudiation"
  toBuilder KeyEncipherment = "keyEncipherment"
  toBuilder DataEncipherment = "dataEncipherment"
  toBuilder KeyAgreement = "keyAgreement"
  toBuilder KeyCertSign = "keyCertSign"
  toBuilder CRLSign = "cRLSign"
  toBuilder EncipherOnly = "encipherOnly"
  toBuilder DecipherOnly = "decipherOnly"


-- | Defines KeyUsage to be a set of @KeyUsageBit@
type KeyUsage = Set KeyUsageBit


instance ToBuilder KeyUsage Builder where
  toBuilder = intersperseCommas . map toBuilder . toList


intersperseCommas :: [Builder] -> Builder
intersperseCommas [] = ""
intersperseCommas (x : xs) = foldl' (\acc y -> acc <> "," <> y) x xs

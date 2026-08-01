{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}

{- |
Module      : DataType.X509.Extension.KeyUsage
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'KeyUsage' extension type.
-}
module DataType.X509.Extension.KeyUsage
  ( KeyUsageBit (..)
  , KeyUsage
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import qualified Data.Set.NonEmpty as NES
import DataType.X509.Extension.Internal (intersperseCommas)


{- | Represents the bits that can set for @KeyUsage@

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
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
  deriving (Eq, Show, Ord, Enum, Bounded)


instance ToBuilder KeyUsageBit Builder where
  toBuilder DigitalSignature = "digitalSignature"
  toBuilder NonRepudiation   = "nonRepudiation"
  toBuilder KeyEncipherment  = "keyEncipherment"
  toBuilder DataEncipherment = "dataEncipherment"
  toBuilder KeyAgreement     = "keyAgreement"
  toBuilder KeyCertSign      = "keyCertSign"
  toBuilder CRLSign          = "cRLSign"
  toBuilder EncipherOnly     = "encipherOnly"
  toBuilder DecipherOnly     = "decipherOnly"


{- | Represents the 'KeyUsage' extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
-}
type KeyUsage = NES.NESet KeyUsageBit


instance ToBuilder KeyUsage Builder where
  toBuilder = intersperseCommas . fmap toBuilder . NES.toList

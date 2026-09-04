{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.ExtKeyUsage
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'ExtKeyUsage' extension type.
-}
module DataType.X509.Extension.ExtKeyUsage
  ( ExtKeyUsagePurpose (..)
  , ExtKeyUsage
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Set.NonEmpty as NES
import DataType.X509.Extension.HasOID (HasOID (..))
import DataType.X509.Extension.Internal (intersperseCommas)


{- | Represents the bits that can set for @ExtKeyUsage@

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
-}
data ExtKeyUsagePurpose
  = ServerAuth
  | ClientAuth
  | CodeSigning
  | EmailProtection
  | TimeStamping
  | OCSPSigning
  | AnyExtendedKeyUsage
  deriving (Eq, Show, Ord, Enum, Bounded)


instance ToBuilder ExtKeyUsagePurpose Builder where
  toBuilder ServerAuth = "serverAuth"
  toBuilder ClientAuth = "clientAuth"
  toBuilder CodeSigning = "codeSigning"
  toBuilder EmailProtection = "emailProtection"
  toBuilder TimeStamping = "timeStamping"
  toBuilder OCSPSigning = "OCSPSigning"
  toBuilder AnyExtendedKeyUsage = "anyExtendedKeyUsage"


{- | Represents the @ExtKeyUsage@ extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
-}
type ExtKeyUsage = NES.NESet ExtKeyUsagePurpose


instance HasOID ExtKeyUsage where
  extensionOID _ = 2 :| [5, 29, 37]


instance ToBuilder ExtKeyUsage Builder where
  toBuilder = intersperseCommas . fmap toBuilder . NES.toList

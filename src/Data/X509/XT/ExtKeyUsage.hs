{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.X509.XT.ExtKeyUsage
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'ExtKeyUsage' extension type.
-}
module Data.X509.XT.ExtKeyUsage
  ( ExtKeyUsagePurpose (..)
  , ExtKeyUsage
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Set.NonEmpty as NES
import Data.X509.XT.HasOID (HasOID (..))
import Data.X509.XT.Internal (intersperseCommas)


{- | Represents the bits that can set for @ExtKeyUsage@

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12 RFC 5280 §4.2.1.12>.
-}
data ExtKeyUsagePurpose
  = -- | TLS WWW server authentication. Renders as @\"serverAuth\"@.
    ServerAuth
  | -- | TLS WWW client authentication. Renders as @\"clientAuth\"@.
    ClientAuth
  | -- | Signing of downloadable executable code. Renders as @\"codeSigning\"@.
    CodeSigning
  | -- | Email protection (S\/MIME). Renders as @\"emailProtection\"@.
    EmailProtection
  | -- | Binding an object hash to a trusted time source. Renders as
    -- @\"timeStamping\"@.
    TimeStamping
  | -- | Signing OCSP responses. Renders as @\"OCSPSigning\"@ (capital OCSP).
    OCSPSigning
  | -- | Permits any extended key usage purpose. Renders as
    -- @\"anyExtendedKeyUsage\"@ (lowercase @any@).
    AnyExtendedKeyUsage
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

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12 RFC 5280 §4.2.1.12>.
-}
type ExtKeyUsage = NES.NESet ExtKeyUsagePurpose


instance HasOID ExtKeyUsage where
  extensionOID _ = 2 :| [5, 29, 37]


instance ToBuilder ExtKeyUsage Builder where
  toBuilder = intersperseCommas . fmap toBuilder . NES.toList

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

Types and smart constructors for the standard X.509 certificate extensions,
with rendering to OpenSSL configuration format via 'asByteString'.

This library is encode-only; no parser or decoder is provided.
-}
module DataType.X509.Extension
  ( -- * Extension types
    BasicConstraints (..)
  , mkBasicConstraints
  , KeyUsageBit (..)
  , KeyUsage
  , ExtKeyUsagePurpose (..)
  , ExtKeyUsage
  , SubjectKeyIdentifier (..)
  , AuthorityKeyIdentifier (..)
  , mkAuthorityKeyIdentifier
  , OID
  , mkOID
  , CertificatePolicies (..)
  , mkCertificatePolicies

    -- * Print types as @ByteString@
  , asByteString

    -- * re-export
  , fromList
  , NonEmpty (..)
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder
  ( Builder
  , byteString
  , intDec
  , toLazyByteString
  )
import Data.List.NonEmpty (NonEmpty (..))
import Data.Set.NonEmpty (fromList)
import qualified Data.Set.NonEmpty as NES
import DataType.X509.Extension.Internal (OID, intersperseCommas, mkOID, oidBuilder)


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


{- | Construct a 'BasicConstraints', validating that @pathLenConstraint@ is
absent when @cA@ is @FALSE@ (RFC 5280 §4.2.1.9).
-}
mkBasicConstraints :: Bool -> Maybe Int -> Either String BasicConstraints
mkBasicConstraints False (Just _) = Left "pathLenConstraint must be absent when cA is FALSE"
mkBasicConstraints isCA pathLen   = Right $ BasicConstraints { bcIsCA = isCA, bcPathLength = pathLen }


instance ToBuilder BasicConstraints Builder where
  toBuilder bc =
    let BasicConstraints{bcIsCA, bcPathLength} = bc
        bcPrefix = "CA:"
        bcSuffix = if bcIsCA then "TRUE" else "FALSE"
        withPathLen x = ",pathLen" <> intDec x
        pathLen = maybe "" withPathLen bcPathLength
     in (bcPrefix <> bcSuffix <> pathLen)


-- | Render an extension value as a strict 'ByteString' in OpenSSL configuration format.
asByteString :: (ToBuilder a Builder) => a -> ByteString
asByteString = BS.toStrict . toLazyByteString . toBuilder


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
  toBuilder NonRepudiation = "nonRepudiation"
  toBuilder KeyEncipherment = "keyEncipherment"
  toBuilder DataEncipherment = "dataEncipherment"
  toBuilder KeyAgreement = "keyAgreement"
  toBuilder KeyCertSign = "keyCertSign"
  toBuilder CRLSign = "cRLSign"
  toBuilder EncipherOnly = "encipherOnly"
  toBuilder DecipherOnly = "decipherOnly"


{- | Represents the 'KeyUsage' extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
-}
type KeyUsage = NES.NESet KeyUsageBit


instance ToBuilder KeyUsage Builder where
  toBuilder = intersperseCommas . fmap toBuilder . NES.toList


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


instance ToBuilder ExtKeyUsage Builder where
  toBuilder = intersperseCommas . fmap toBuilder . NES.toList


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


{- | Represents the AuthorityKeyIdentifier extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
-}
data AuthorityKeyIdentifier = AuthorityKeyIdentifier
  { akiKeyId :: !Bool
  -- ^ include key ID
  , akiKeyIdAlways :: !Bool
  -- ^ always include the key identifier, even if the issuer certificate
  -- has no SubjectKeyIdentifier extension
  , akiIssuer :: !Bool
  -- ^ include issuer name + serial
  , akiIssuerAlways :: !Bool
  -- ^ always include
  }
  deriving (Eq, Show)


{- | Construct an 'AuthorityKeyIdentifier', normalising the @always@ flags:
if @keyIdAlways@ is 'True', @keyId@ is set to 'True'; if @issuerAlways@ is
'True', @issuer@ is set to 'True'.
-}
mkAuthorityKeyIdentifier :: Bool -> Bool -> Bool -> Bool -> AuthorityKeyIdentifier
mkAuthorityKeyIdentifier keyId keyIdAlways issuer issuerAlways =
  AuthorityKeyIdentifier
    { akiKeyId        = keyId   || keyIdAlways
    , akiKeyIdAlways  = keyIdAlways
    , akiIssuer       = issuer  || issuerAlways
    , akiIssuerAlways = issuerAlways
    }


instance ToBuilder AuthorityKeyIdentifier Builder where
  toBuilder aki =
    let keyId =
          if akiKeyIdAlways aki
            then Just "keyid:always"
            else if akiKeyId aki then Just "keyid" else Nothing
        issuer =
          if akiIssuerAlways aki
            then Just "issuer:always"
            else if akiIssuer aki then Just "issuer" else Nothing
     in case (keyId, issuer) of
          (Nothing, Nothing) -> mempty
          (Nothing, Just x) -> x
          (Just x, Nothing) -> x
          (Just x, Just y) -> intersperseCommas (x :| [y])


{- | Represents @CertificatePolicies@ (RFC 5280 §4.2.1.4).

Only the policy OIDs are modelled. @PolicyQualifierInfo@ entries (CPS URIs,
user notices) are not yet supported.
-}
newtype CertificatePolicies = CertificatePolicies (NonEmpty OID)
  deriving (Eq, Show)


-- | Construct @CertificatePolicies@
mkCertificatePolicies :: OID -> [OID] -> CertificatePolicies
mkCertificatePolicies x xs = CertificatePolicies $ x :| xs


instance ToBuilder CertificatePolicies Builder where
  toBuilder (CertificatePolicies xs) = intersperseCommas $ fmap oidBuilder xs

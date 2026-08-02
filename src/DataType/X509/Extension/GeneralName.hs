{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.GeneralName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'GeneralName', the common name type used across several X.509
extensions, including SubjectAltName and AuthorityInfoAccess.

'DirectoryName', x400Address, and ediPartyName are not yet modelled.
-}
module DataType.X509.Extension.GeneralName
  ( GeneralName (..)
  , OtherName (..)
  , Asn1StringType (..)
  , mkDNSName
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder, byteString)
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import DataType.X509.Extension.Internal (OID, oidBuilder)
import Net.IP (IP)
import qualified Net.IP as IP
import Text.Email.Validate (EmailAddress)
import qualified Text.Email.Validate as Email
import Text.URI (URI)
import qualified Text.URI as URI


{- | A general name as defined in RFC 5280 §4.1.2.6.

Used in extensions such as SubjectAltName and AuthorityInfoAccess.
-}
data GeneralName
  = {- | A DNS hostname. Rendered as @DNS:\<name\>@. Prefer 'mkDNSName' to
    validate the hostname before construction.
    -}
    DNSName !Text
  | -- | An IPv4 or IPv6 address. Rendered as @IP:\<address\>@.
    IPAddr !IP
  | -- | An email address. Rendered as @email:\<address\>@.
    EmailAddr !EmailAddress
  | -- | A URI. Rendered as @URI:\<uri\>@.
    URIName !URI
  | -- | An ASN.1 registered object identifier. Rendered as @RID:\<oid\>@.
    RegisteredID !OID
  | {- | An arbitrary other name. Rendered as
    @otherName:\<oid\>;\<type\>:\<value\>@, where @\<type\>@ is the
    OpenSSL tag string for the 'Asn1StringType'.
    -}
    Other !OtherName
  deriving (Eq, Show)


{- | The fields of an @otherName@ general name (RFC 5280 §4.1.2.6).

Carries the type OID, the ASN.1 string encoding, and the string value.
-}
data OtherName = OtherName
  { onTypeId   :: !OID           -- ^ OID identifying the name type.
  , onEncoding :: !Asn1StringType -- ^ ASN.1 string encoding for the value.
  , onValue    :: !Text           -- ^ The string value.
  }
  deriving (Eq, Show)


-- | The ASN.1 string encoding tag for an 'OtherName' value.
data Asn1StringType
  = UTF8String      -- ^ UTF-8 encoding. Rendered as @UTF8@.
  | IA5String       -- ^ ASCII (IA5) encoding. Rendered as @IA5@.
  | PrintableString -- ^ PrintableString encoding. Rendered as @PRINTABLE@.
  | BMPString       -- ^ BMP (UCS-2) encoding. Rendered as @BMP@.
  deriving (Eq, Show)


instance ToBuilder Asn1StringType Builder where
  toBuilder UTF8String      = "UTF8"
  toBuilder IA5String       = "IA5"
  toBuilder PrintableString = "PRINTABLE"
  toBuilder BMPString       = "BMP"


instance ToBuilder GeneralName Builder where
  toBuilder (DNSName t)           = "DNS:" <> byteString (TE.encodeUtf8 t)
  toBuilder (IPAddr ip)           = "IP:" <> byteString (TE.encodeUtf8 (IP.encode ip))
  toBuilder (EmailAddr addr)      = "email:" <> byteString (Email.toByteString addr)
  toBuilder (URIName uri)         = "URI:" <> byteString (TE.encodeUtf8 (URI.render uri))
  toBuilder (RegisteredID o) = "RID:" <> oidBuilder o
  toBuilder (Other on)       =
    "otherName:" <> oidBuilder (onTypeId on) <> ";" <> toBuilder (onEncoding on) <> ":" <> byteString (TE.encodeUtf8 (onValue on))


{- | Construct a 'DNSName', validating against RFC 1123 hostname rules.

Returns @Left@ with a description if the name is invalid. Accepts a wildcard
@*@ as the first label (e.g. @\"*.example.com\"@). IDNA\/punycode encoding of
Unicode hostnames must be done by the caller before passing to this function.
-}
mkDNSName :: Text -> Either String GeneralName
mkDNSName t
  | T.null t = Left "DNS name must not be empty"
  | T.length t > 253 = Left "DNS name exceeds 253 characters"
  | otherwise = validateLabels (T.splitOn "." t) >> Right (DNSName t)
 where
  validateLabels [] = Left "DNS name must not be empty"
  validateLabels (l : ls) = validateFirst l >> mapM_ validateLabel ls

  validateFirst "*" = Right ()
  validateFirst l = validateLabel l

  validateLabel l
    | T.null l = Left "DNS label must not be empty"
    | T.length l > 63 = Left $ "DNS label exceeds 63 characters: " <> T.unpack l
    | otherwise =
        case (T.uncons l, T.unsnoc l) of
          (Just ('-', _), _) -> Left $ "DNS label must not start with hyphen: " <> T.unpack l
          (_, Just (_, '-')) -> Left $ "DNS label must not end with hyphen: " <> T.unpack l
          _
            | T.all isValidChar l -> Right ()
            | otherwise -> Left $ "DNS label contains invalid character: " <> T.unpack l

  isValidChar c = isAlphaNum c || c == '-'



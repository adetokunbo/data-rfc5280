{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.Generators
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Shared QuickCheck generators for X.509 extension test suites.
-}
module X509.Extension.Generators
  ( validLabel
  , validDNSName
  , validDnsName
  , nameWithInvalidChar
  , vectorOf1
  )
where

import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Text as T
import DataType.X509.Extension.GeneralName (DnsName, mkDnsName)
import Test.QuickCheck (Gen, choose, elements, vectorOf)


-- | Generates a DNS label of 1–10 lowercase alphanumeric characters.
validLabel :: Gen T.Text
validLabel = do
  n <- choose (1, 10)
  T.pack <$> vectorOf n (elements (['a' .. 'z'] ++ ['0' .. '9']))


-- | Generates a valid DNS name of 1–4 alphanumeric-only labels.
validDNSName :: Gen T.Text
validDNSName = do
  n <- choose (1, 4)
  labels <- vectorOf n validLabel
  return $ T.intercalate "." labels


{- | Generates a valid 'DnsName'.

Wraps 'validDNSName' and applies 'mkDnsName'; panics if the generator
produces an invalid name (which it never should).
-}
validDnsName :: Gen DnsName
validDnsName = do
  t <- validDNSName
  case mkDnsName t of
    Right dn -> return dn
    Left err -> error $ "validDNSName produced invalid DNS name: " <> show err


{- | Like 'vectorOf' but returns a 'NonEmpty' list, guaranteeing at least one
element. The count @n@ must be ≥ 1; callers should enforce this with
'choose' or similar.
-}
vectorOf1 :: Int -> Gen a -> Gen (NonEmpty a)
vectorOf1 n gen = do
  h  <- gen
  tl <- vectorOf (n - 1) gen
  return (h :| tl)


-- | Generates a single label with one invalid character injected in the middle.
nameWithInvalidChar :: Gen T.Text
nameWithInvalidChar = do
  prefix  <- validLabel
  badChar <- elements "!@#$%^&*()"
  suffix  <- validLabel
  return $ prefix <> T.singleton badChar <> suffix

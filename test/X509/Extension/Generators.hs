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
  , nameWithInvalidChar
  )
where

import qualified Data.Text as T
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


-- | Generates a single label with one invalid character injected in the middle.
nameWithInvalidChar :: Gen T.Text
nameWithInvalidChar = do
  prefix  <- validLabel
  badChar <- elements "!@#$%^&*()"
  suffix  <- validLabel
  return $ prefix <> T.singleton badChar <> suffix

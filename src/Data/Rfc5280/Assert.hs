{- |
Module      : Data.Rfc5280.Assert
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Helpers for lifting RFC 5280 smart-constructor results into 'MonadFail'.

'assertRight' and 'assertJust' convert the two common failure containers
('Either' and 'Maybe') into any 'MonadFail' context, producing a clear
failure message when the value is absent.
-}
module Data.Rfc5280.Assert
  ( assertRight
  , assertJust
  )
where


{- | Lift an @Either e a@ into any 'MonadFail', calling 'fail' with 'show' of
the error on 'Left'.
-}
assertRight :: (Show e, MonadFail m) => Either e a -> m a
assertRight = either (fail . show) pure


{- | Lift a @Maybe a@ into any 'MonadFail', calling 'fail' with the given
message on 'Nothing'.
-}
assertJust :: (MonadFail m) => String -> Maybe a -> m a
assertJust msg = maybe (fail msg) pure

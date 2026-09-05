{- |
Module      : Data.Rfc5280.Assert
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Helpers for lifting RFC 5280 smart-constructor results into 'MonadIO'.

'assertRight' and 'assertJust' convert the two common failure containers
('Either' and 'Maybe') into any 'MonadIO' context, throwing a 'userError'
when the value is absent.
-}
module Data.Rfc5280.Assert
  ( assertRight
  , assertJust
  )
where

import Control.Exception (throwIO)
import Control.Monad.IO.Class (MonadIO, liftIO)


{- | Lift an @Either e a@ into any 'MonadIO', throwing a 'userError' with
'show' of the error on 'Left'.
-}
assertRight :: (Show e, MonadIO m) => Either e a -> m a
assertRight = either (liftIO . throwIO . userError . show) pure


{- | Lift a @Maybe a@ into any 'MonadIO', throwing a 'userError' with the
given message on 'Nothing'.
-}
assertJust :: (MonadIO m) => String -> Maybe a -> m a
assertJust msg = maybe (liftIO . throwIO . userError $ msg) pure

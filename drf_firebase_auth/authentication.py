# -*- coding: utf-8 -*-
"""
Authentication backend for handling firebase user.idToken from incoming
Authorization header, verifying, and locally authenticating
"""
from typing import Tuple, Dict
import logging

import firebase_admin
from firebase_admin import auth as firebase_auth
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework import (
    authentication,
    exceptions
)

from .settings import api_settings
from .models import (
    FirebaseUser,
    FirebaseUserProvider
)
from .utils import get_firebase_user_email
from . import __title__

log = logging.getLogger(__title__)
User = get_user_model()

firebase_credentials = firebase_admin.credentials.Certificate(
    api_settings.FIREBASE_SERVICE_ACCOUNT_KEY
)
firebase = firebase_admin.initialize_app(
    credential=firebase_credentials,
)


class FirebaseAuthentication(authentication.TokenAuthentication):
    """
    Token based authentication using firebase.
    """
    keyword = api_settings.FIREBASE_AUTH_HEADER_PREFIX

    def authenticate_credentials(
        self,
        token: str
    ) -> Tuple[AnonymousUser, Dict]:
        try:
            decoded_token = self._decode_token(token)
            firebase_user = self._authenticate_token(decoded_token)
            local_user = self._get_or_create_local_user(firebase_user)
            self._create_local_firebase_user(local_user, firebase_user)
            return (local_user, decoded_token)
        except Exception as e:
            raise exceptions.AuthenticationFailed(e)

    def _decode_token(self, token: str) -> Dict:
        """
        Attempt to verify JWT from Authorization header with Firebase and
        return the decoded token
        """
        try:
            decoded_token = firebase_auth.verify_id_token(
                token,
                check_revoked=api_settings.FIREBASE_CHECK_JWT_REVOKED
            )
            log.info(f'_decode_token - decoded_token: {decoded_token}')
            return decoded_token
        except Exception as e:
            log.error(f'_decode_token - Exception: {e}')
            raise Exception(e)

    def _authenticate_token(
        self,
        decoded_token: Dict
    ) -> firebase_auth.UserRecord:
        """ Returns firebase user if token is authenticated """
        try:
            uid = decoded_token.get('uid')
            log.info(f'_authenticate_token - uid: {uid}')
            firebase_user = firebase_auth.get_user(uid)
            log.info(f'_authenticate_token - firebase_user: {firebase_user}')
            if api_settings.FIREBASE_AUTH_EMAIL_VERIFICATION:
                if not firebase_user.email_verified:
                    raise Exception(
                        'Email address of this user has not been verified.'
                    )
            return firebase_user
        except Exception as e:
            log.error(f'_authenticate_token - Exception: {e}')
            raise Exception(e)

    def _get_or_create_local_user(
        self,
        firebase_user: firebase_auth.UserRecord
    ) -> User:
        """
        Attempts to return or create a local User based on the firebase_user UID.
        This allows multiple FirebaseUsers to share the same email, as each
        UID now maps to its own unique local User.
        """
        uid = firebase_user.uid
        log.info(f'_get_or_create_local_user - uid: {uid}')

        # Try looking up an existing FirebaseUser with the matching UID
        local_firebase_user = FirebaseUser.objects.filter(uid=uid).first()
        if local_firebase_user:
            # Existing user found
            user = local_firebase_user.user
            if not user.is_active:
                raise Exception('User account is not currently active.')

            # Update last login
            user.last_login = timezone.now()
            user.save()
            return user

        # If we reach here, we have no existing record with that UID.
        if not api_settings.FIREBASE_CREATE_LOCAL_USER:
            raise Exception('User is not registered to the application.')

        # Create a brand new local user
        email = get_firebase_user_email(firebase_user)
        username = api_settings.FIREBASE_USERNAME_MAPPING_FUNC(firebase_user)
        log.info(f'_get_or_create_local_user - Creating new user for UID {uid} with username: {username}')

        try:
            user = User.objects.create_user(
                username=username,
                email=email  # Allow duplicates since we don't rely on it for uniqueness
            )
            user.last_login = timezone.now()

            # Optionally fill in first/last name from display_name
            if (
                    api_settings.FIREBASE_ATTEMPT_CREATE_WITH_DISPLAY_NAME
                    and firebase_user.display_name is not None
            ):
                display_name = firebase_user.display_name.split(' ')
                if len(display_name) == 2:
                    user.first_name = display_name[0]
                    user.last_name = display_name[1]

            user.save()

        except Exception as e:
            raise Exception(e)

        return user

    def _create_local_firebase_user(
            self,
            user: User,
            firebase_user: firebase_auth.UserRecord
    ):
        """
        Create or update a local FirebaseUser model if needed,
        ensuring each unique Firebase UID is handled independently.
        """
        local_firebase_user = FirebaseUser.objects.filter(user=user).first()

        # If the user is missing a FirebaseUser record or has a different UID, fix it
        if not local_firebase_user or local_firebase_user.uid != firebase_user.uid:
            FirebaseUser.objects.update_or_create(
                user=user,
                defaults={'uid': firebase_user.uid}
            )
            local_firebase_user = FirebaseUser.objects.get(user=user)

        # Store or update FirebaseUserProvider data
        for provider in firebase_user.provider_data:
            local_provider = FirebaseUserProvider.objects.filter(
                provider_id=provider.provider_id,
                firebase_user=local_firebase_user
            ).first()

            if not local_provider:
                FirebaseUserProvider.objects.create(
                    provider_id=provider.provider_id,
                    uid=provider.uid,
                    firebase_user=local_firebase_user,
                )

        # Remove any locally stored providers that Firebase no longer reports
        local_providers = FirebaseUserProvider.objects.filter(
            firebase_user=local_firebase_user
        )
        current_providers = [x.provider_id for x in firebase_user.provider_data]
        for provider in local_providers:
            if provider.provider_id not in current_providers:
                provider.delete()
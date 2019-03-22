import importlib
import logging
import re
import typing
from functools import partial
from inspect import isawaitable

import aiohttp
from aiohttp.web_exceptions import HTTPBadRequest, HTTPUnauthorized
from sanic import Blueprint, Sanic
from sanic.request import Request
from sanic.response import HTTPResponse, redirect
from sanic_session import Session
from .core import UserInfo

__author__ = "Bogdan Gladyshev"
__copyright__ = "Copyright 2017, Bogdan Gladyshev"
__credits__ = ["Bogdan Gladyshev"]
__license__ = "MIT"
__version__ = "0.4.0"
__maintainer__ = "Bogdan Gladyshev"
__email__ = "siredvin.dark@gmail.com"
__status__ = "Production"

_log = logging.getLogger(__name__)

oauth_blueprint = Blueprint('OAuth Configuration')  # pylint: disable=invalid-name


class OAuthConfigurationException(Exception):
    pass


async def oauth(request: Request) -> HTTPResponse:
    provider = request['session'].get('oauth_provider', None)
    provider_confs = request.app.config.get('OAUTH_PROVIDERS', {})
    if provider is None and 'default' in provider_confs:
        provider = 'default'
    if provider:
        if provider not in provider_confs:
            return HTTPResponse(status=404)
        provider_conf = provider_confs[provider]
        use_scope = provider_conf['SCOPE']
        use_redirect_uri = provider_conf['REDIRECT_URI']
        use_after_auth_default_redirect = \
            provider_conf['AFTER_AUTH_DEFAULT_REDIRECT']
    else:
        use_scope = request.app.config.OAUTH_SCOPE
        use_redirect_uri = request.app.config.OAUTH_REDIRECT_URI
        use_after_auth_default_redirect = \
            request.app.config.OAUTH_AFTER_AUTH_DEFAULT_REDIRECT
    client = request.app.oauth_factory(provider=provider)
    if 'code' not in request.args:
        return redirect(client.get_authorize_url(
            scope=use_scope,
            redirect_uri=use_redirect_uri
        ))

    token, _data = await client.get_access_token(
        request.args.get('code'),
        redirect_uri=use_redirect_uri
    )
    request['session']['token'] = token
    if provider:
        # remember provider
        request['session']['oauth_provider'] = provider
    elif 'oauth_provider' in request['session']:
        # forget remembered provider
        del request['session']['oauth_provider']
    return redirect(request['session'].get('after_auth_redirect',
                                           use_after_auth_default_redirect))


async def oauth_logout(request: Request) -> HTTPResponse:
    del request['session']['token']
    del request['session']['user_info']
    logout_uri = request.app.config.OAUTH_LOGOUT_URI
    return redirect(logout_uri)


async def oauth_login(request: Request) -> HTTPResponse:
    provider = None
    oauth_endpoint_path = None
    oauth_email_regex = None
    provider_confs = request.app.config.get('OAUTH_PROVIDERS', {})
    if provider is None and 'default' in provider_confs:
        provider = 'default'

    if provider:
        try:
            provider_config = provider_confs[provider]
        except KeyError:
            if provider == "default" and provider_confs:
                provider_config = next(iter(provider_confs.values()))
            else:
                raise OAuthConfigurationException(
                    "No provider named {} configured".format(provider))
        oauth_endpoint_path = provider_config.get('ENDPOINT_PATH', None)
        oauth_email_regex = provider_config.get('EMAIL_REGEX', None)

    if not oauth_endpoint_path:
        oauth_endpoint_path = request.app.config.OAUTH_ENDPOINT_PATH

    return redirect(oauth_endpoint_path)

async def fetch_user_info(request, provider, oauth_endpoint_path, local_email_regex) -> UserInfo:
    try:
        user_info = request['session']['user_info']
        user = UserInfo(**user_info)
    except KeyError:
        factory_args = {'access_token': request['session']['token']}
        oauth_provider = request['session'].get('oauth_provider', provider)
        if oauth_provider:
            factory_args['provider'] = provider
        client = request.app.oauth_factory(**factory_args)

        try:
            user, _info = await client.user_info()
        except (KeyError, HTTPBadRequest) as exc:
            _log.exception(exc)
            return redirect(oauth_endpoint_path)

        if local_email_regex and user.email:
            if not local_email_regex.match(user.email):
                return redirect(oauth_endpoint_path)
        request['session']['user_info'] = _info
    return user


def login_required(async_handler=None, provider=None, add_user_info=True, email_regex=None, redirect_login=True):
    """
    auth decorator
    call function(request, user: <sanic_oauth UserInfo object>)
    """

    if async_handler is None:
        return partial(login_required, provider=provider, add_user_info=add_user_info, email_regex=email_regex, redirect_login=redirect_login)

    if email_regex is not None:
        email_regex = re.compile(email_regex)

    async def wrapped(request, **kwargs):
        nonlocal provider
        oauth_endpoint_path = None
        oauth_email_regex = None
        provider_confs = request.app.config.get('OAUTH_PROVIDERS', {})
        if provider is None and 'default' in provider_confs:
            provider = 'default'

        if provider:
            try:
                provider_config = provider_confs[provider]
            except KeyError:
                if provider == "default" and provider_confs:
                    provider_config = next(iter(provider_confs.values()))
                else:
                    raise OAuthConfigurationException(
                        "No provider named {} configured".format(provider))
            oauth_endpoint_path = provider_config.get('ENDPOINT_PATH', None)
            oauth_email_regex = provider_config.get('EMAIL_REGEX', None)

        if not oauth_endpoint_path:
            oauth_endpoint_path = request.app.config.OAUTH_ENDPOINT_PATH

        if not oauth_email_regex:
            oauth_email_regex = request.app.config.OAUTH_EMAIL_REGEX

        # Do core oauth authentication once per session
        if 'token' not in request['session']:
            if not redirect_login:
                raise HTTPUnauthorized(reason=f'User is not authenticated.')

            if provider:
                request['session']['oauth_provider'] = provider
            request['session']['after_auth_redirect'] = request.path
            return redirect(oauth_endpoint_path)

        # Shortcircuit out if we don't care about user info
        if not add_user_info:
            response = async_handler(request, **kwargs)
        else:
            # Otherwise retrieve the user info once per session
            user = await fetch_user_info(
                request, provider, oauth_endpoint_path,
                email_regex or oauth_email_regex
            )

            if user is None:
                raise HTTPUnauthorized(reason=f'Cannot fetch user info.')

            response = async_handler(request, user, **kwargs)

        return await response if isawaitable(response) else response

    return wrapped


auth_required = partial(login_required, redirect_login=False)


def setup_providers(  # pylint: disable=too-many-locals
        providers_conf: typing.Dict, oauth_redirect_uri: str,
        oauth_scope: str, oauth_endpoint_path: str) -> typing.Dict:
    from .core import Client

    providers = {}
    for provider_name, provider_conf in providers_conf.items():
        provider_conf.setdefault('AFTER_AUTH_DEFAULT_REDIRECT', '/')
        p_class_link = provider_conf.pop('PROVIDER_CLASS', None)
        if p_class_link is None:
            raise OAuthConfigurationException("Provider config must have PROVIDER_CLASS set.")
        redirect_uri = provider_conf.pop('REDIRECT_URI', oauth_redirect_uri)
        if redirect_uri is None:
            raise OAuthConfigurationException(
                "Provider config must have REDIRECT_URI set when there is no global OAUTH_REDIRECT_URI set."
            )
        scope = provider_conf.pop('SCOPE', oauth_scope)
        if scope is None:
            raise OAuthConfigurationException(
                "Provider config must have SCOPE set when there is no global OAUTH_SCOPE set."
            )
        endpoint_path = provider_conf.pop('ENDPOINT_PATH', oauth_endpoint_path)
        p_module_path, p_class_name = p_class_link.rsplit('.', 1)
        module_obj = importlib.import_module(p_module_path)
        if module_obj is None:
            raise OAuthConfigurationException(
                f"Cannot find module {p_module_path} to import OAuth provider")
        p_class = getattr(module_obj, p_class_name, None)
        if p_class is None:
            raise OAuthConfigurationException(
                f"Cannot find class {p_class_name} in module {p_module_path}")
        if not issubclass(p_class, Client):
            raise OAuthConfigurationException(
                f"Class must be a child of sanic_oauth.core.Client class")
        provider_listing = {'provider_class': p_class}
        provider_setting = {k.lower(): v for k, v in provider_conf.items()}
        provider_listing['provider_setting'] = provider_setting
        provider_conf['PROVIDER_CLASS'] = p_class_link
        provider_conf['REDIRECT_URI'] = redirect_uri
        provider_conf['SCOPE'] = scope
        provider_conf['ENDPOINT_PATH'] = endpoint_path
        providers[provider_name] = provider_listing
    return providers


def legacy_oauth_configuration(
        sanic_app: Sanic, provider_class_link: str,
        oauth_redirect_uri: str, oauth_scope: str):
    from .core import Client

    client_setting = {
        config_key[6:].lower(): sanic_app.config.get(config_key)
        for config_key in sanic_app.config.keys() if config_key.startswith('OAUTH')
    }

    if provider_class_link is None:
        raise OAuthConfigurationException("You should setup OAUTH_PROVIDER setting for app")
    if oauth_redirect_uri is None:
        raise OAuthConfigurationException("You should setup OAUTH_REDIRECT_URI setting for app")
    if oauth_scope is None:
        raise OAuthConfigurationException("You should setup OAUTH_SCOPE setting for app")
    if provider_class_link:
        provider_module_path, provider_class_name = provider_class_link.rsplit('.', 1)
        module_object = importlib.import_module(provider_module_path)
        if module_object is None:
            raise OAuthConfigurationException(f"Cannot find module {provider_module_path} to import OAuth provider")
        provider_class = getattr(module_object, provider_class_name, None)
        if provider_class is None:
            raise OAuthConfigurationException(
                f"Cannot find class {provider_class_name} in module {provider_module_path}"
            )
        if not issubclass(provider_class, Client):
            raise OAuthConfigurationException("Class must be a child of sanic_oauth.core.Client class")
    return client_setting, provider_class


@oauth_blueprint.listener('after_server_start')
async def create_oauth_factory(sanic_app: Sanic, _loop) -> None:
    from .core import Client

    sanic_app.config.setdefault('OAUTH_AFTER_AUTH_DEFAULT_REDIRECT', '/')
    oauth_redirect_uri: str = sanic_app.config.pop('OAUTH_REDIRECT_URI', None)
    oauth_scope: str = sanic_app.config.pop('OAUTH_SCOPE', None)
    oauth_endpoint_path: str = sanic_app.config.pop('OAUTH_ENDPOINT_PATH', '/oauth')
    oauth_email_regex: str = sanic_app.config.pop('OAUTH_EMAIL_REGEX', None)
    providers_conf = sanic_app.config.pop('OAUTH_PROVIDERS', {})
    providers: typing.Optional[typing.Dict] = None
    if providers_conf:
        providers = setup_providers(
            providers_conf, oauth_redirect_uri,
            oauth_scope, oauth_endpoint_path
        )
        _, p_listing = next(iter(providers.items()))
        provider_class = p_listing['provider_class']
        client_setting = p_listing['provider_setting']
    else:
        provider_class_link: str = sanic_app.config.pop('OAUTH_PROVIDER', None)
        client_setting, provider_class = legacy_oauth_configuration(
            sanic_app, provider_class_link,
            oauth_redirect_uri, oauth_scope
        )

    def oauth_factory(access_token: str = None, provider=None) -> Client:
        if provider is not None:
            if providers is None:
                raise OAuthConfigurationException(
                    "You can use provider mark only when multiple providers are configured"
                )
            provider_listing = providers[provider]
            use_provider_class = provider_listing['provider_class']
            use_client_setting = provider_listing['provider_setting']
        else:
            use_provider_class = provider_class
            use_client_setting = client_setting
        result = use_provider_class(
            sanic_app.async_session,
            access_token=access_token,
            **use_client_setting
        )
        return result

    sanic_app.oauth_factory = oauth_factory
    sanic_app.config.OAUTH_REDIRECT_URI = oauth_redirect_uri
    sanic_app.config.OAUTH_SCOPE = oauth_scope
    sanic_app.config.OAUTH_ENDPOINT_PATH = oauth_endpoint_path
    if providers_conf:
        sanic_app.config.OAUTH_PROVIDERS = providers_conf

    if oauth_email_regex:
        sanic_app.config.OAUTH_EMAIL_REGEX = re.compile(oauth_email_regex)
    else:
        sanic_app.config.OAUTH_EMAIL_REGEX = None

    sanic_app.add_route(oauth, oauth_endpoint_path)
    sanic_app.add_route(oauth_logout, oauth_endpoint_path + '/logout')
    sanic_app.add_route(oauth_login, oauth_endpoint_path + '/login')


@oauth_blueprint.listener('after_server_start')
async def configuration_check(sanic_app: Sanic, _loop) -> None:
    if not hasattr(sanic_app, 'async_session'):
        raise OAuthConfigurationException("You should configure async_session with aiohttp.ClientSession")

    extensions = getattr(sanic_app, 'extensions', None) or dict()
    if not any(isinstance(e, Session) for e in extensions.values()):
        raise OAuthConfigurationException(
            "You should configure Session from [sanic-session]"
            "(https://sanic-session.readthedocs.io/en/latest/using_the_interfaces.html)"
        )


@oauth_blueprint.listener('before_server_start')
async def init_aiohttp_session(sanic_app: Sanic, _loop) -> None:
    sanic_app.async_session = aiohttp.ClientSession()


@oauth_blueprint.listener('after_server_stop')
async def close_aiohttp_session(sanic_app: Sanic, _loop) -> None:
    await sanic_app.async_session.close()

from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect, resolve_url
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import login, logout

from two_factor import signals
from two_factor.forms import AuthenticationTokenForm, BackupTokenForm
from two_factor.views.core import LoginView
from otp_yubikey.models import ValidationService

from fir_auth_2fa.forms import CustomAuthenticationTokenForm
from incidents.models import Profile
from incidents.forms import CustomAuthenticationForm
from incidents.views import init_session, log


class CustomLoginView(LoginView):
    template_name = "two_factor/login.html"

    form_list = (
        ("auth", CustomAuthenticationForm),
        ("token", CustomAuthenticationTokenForm),
        ("backup", BackupTokenForm),
    )

    def __init__(self, **kwargs):
        try:

            if ValidationService.objects.count() == 0:
                # Validate Yubikey against YubiCloud by default
                ValidationService.objects.create(
                    name="default", use_ssl=True, param_sl="", param_timeout=""
                )
        except ImportError:
            pass
        super(CustomLoginView, self).__init__(**kwargs)

    def post(self, *args, **kwargs):
        if not self.request.POST.get(
            "auth-remember", None
        ) and not "token" in self.request.POST.get(
            "custom_login_view-current_step", []
        ):
            self.request.session.set_expiry(0)
        return super(CustomLoginView, self).post(**kwargs)

    def done(self, form_list, **kwargs):
        """
        Login the user and redirect to the desired page.
        """
        login(self.request, self.get_user())

        redirect_to = self.request.POST.get(
            self.redirect_field_name, self.request.GET.get(self.redirect_field_name, "")
        )
        if not url_has_allowed_host_and_scheme(
            url=redirect_to, allowed_hosts=self.request.get_host()
        ):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

        is_auth = False
        user = self.get_user()
        device = getattr(self.get_user(), "otp_device", None)
        if device:
            signals.user_verified.send(
                sender=__name__,
                request=self.request,
                user=self.get_user(),
                device=device,
            )
            redirect_to = resolve_url("dashboard:main")
            is_auth = True
        elif hasattr(settings, "ENFORCE_2FA") and settings.ENFORCE_2FA:
            redirect_to = resolve_url("two_factor:profile")
        else:
            redirect_to = resolve_url("dashboard:main")
            is_auth = True
        try:
            Profile.objects.get(user=user)
        except ObjectDoesNotExist:
            profile = Profile()
            profile.user = user
            profile.hide_closed = False
            profile.incident_number = 50
            profile.save()
        if user.is_active:
            log("Login success", user)
            init_session(self.request)
        return redirect(redirect_to)
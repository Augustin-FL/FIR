from django.urls import re_path

from fir_yeti import views, api

app_name = "fir_yeti"

urlpatterns = [
    re_path(r"^update_api", views.update_api, name="update_api"),
]

api_urls = [
    ("yeti", api.YetiViewSet),
]

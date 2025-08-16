from django.urls import path
from assets.api.views import AssetBulkFetchView

urlpatterns = [
    path("", AssetBulkFetchView.as_view(), name="assets-by-ids"),
]
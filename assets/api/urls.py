from rest_framework.routers import DefaultRouter

from assets.api.views import AssetViewSet

router = DefaultRouter()
router.register(r'', AssetViewSet)
urlpatterns = router.urls
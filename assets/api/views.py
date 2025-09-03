from rest_framework import viewsets
from assets.models import Asset
from assets.api.serializers import AssetSerializer


class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
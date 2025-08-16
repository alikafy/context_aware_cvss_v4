from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from assets.models import Asset
from assets.api.serializers import AssetSerializer


class AssetBulkFetchView(APIView):
    """
    GET  /api/assets/by-ids/?ids=1,2,3
    POST /api/assets/by-ids/  {"ids": [1,2,3]}

    If ids is null/empty/missing => return all assets.
    """

    def get(self, request):
        ids = request.query_params.get("ids", None)
        return self._respond(ids)

    def _respond(self, ids):
        qs = Asset.objects.all()

        # treat null/empty as "return all"
        if ids in (None, "", [], "null", "None"):
            serializer = AssetSerializer(qs, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # accept comma-separated string or list
        if isinstance(ids, str):
            ids = [part.strip() for part in ids.split(",") if part.strip()]

        try:
            id_list = [int(x) for x in ids]
        except (TypeError, ValueError):
            return Response(
                {"detail": "ids must be a list of integers or a comma-separated string of integers."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = qs.filter(id__in=id_list)
        serializer = AssetSerializer(qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

import logging
from pymisp.exceptions import PyMISPError

from django.conf import settings
from django.utils.translation import gettext_lazy as _

from rest_framework import viewsets, status, serializers, mixins
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import APIException
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from django_filters.rest_framework import CharFilter, FilterSet

from fir_api.permissions import CanViewIncident, CanWriteIncident
from fir_api.renderers import FilterButtonBrowsableAPIRenderer
from fir_api.filter_backends import DummyFilterBackend

from fir_misp.models import MISPProfile
from fir_misp.mispclient import MISPClient


class MISPFilter(FilterSet):
    observable = CharFilter(label=_("observable"))
    incident_id = CharFilter(label=_("incident_id"))


class MISPSerializer(serializers.Serializer):
    observables = serializers.JSONField(
        initial=[
            {
                "observables": [{"value": "example.com", "tags": ["malware"]}],
                "misp_events": [{"value": "1234"}],
                "fid": "FIR-1234",
            }
        ]
    )


class MISPViewSet(
    viewsets.GenericViewSet,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
):
    """
    Interact with MISP attributes
    """

    serializer_class = MISPSerializer
    permission_classes = [IsAuthenticated, CanViewIncident | CanWriteIncident]
    queryset = MISPProfile.objects.none()
    filterset_class = MISPFilter
    filter_backends = [DummyFilterBackend]
    renderer_classes = [JSONRenderer, FilterButtonBrowsableAPIRenderer]

    def get_mp(self, user):
        mp, _ = MISPProfile.objects.get_or_create(user_id=user)
        # Allow MISP connection to be defined via global settings
        if (
            not mp.endpoint
            and not mp.api_key
            and hasattr(settings, "MISP_URL")
            and hasattr(settings, "MISP_APIKEY")
        ):
            mp.endpoint = settings.MISP_URL
            mp.api_key = settings.MISP_APIKEY
        py_misp = MISPClient(mp.endpoint, mp.api_key)
        mp.py_misp = py_misp
        return py_misp

    def get_misp_related_events(self, user, tags_to_search):
        try:
            mp = self.get_mp(user)
            tags_list = mp.searchtag(tags_to_search)
            related_events = []
            if len(tags_list) > 0:
                tags_list = tags_list[0]
                for elt in tags_list["result"]:
                    entry = {}
                    entry["url"] = f"{tags_list['url']}/events/view/{elt['id']}"
                    entry["event_id"] = elt["id"]
                    entry["org_name"] = str(elt["Orgc"]["name"])
                    entry["event_tags"] = [t["name"] for t in elt["Tag"]]
                    entry["date"] = str(elt["date"])
                    entry["info"] = str(elt["info"])
                    related_events.append(entry)
            return related_events
        except PyMISPError as err:
            logging.error(f"Got PyMISPError into get_misp_related_events: {err}")
            return []

    def list(self, request, *args, **kwargs):
        self.filter_queryset(self.get_queryset())
        observables = request.query_params.getlist("observable")
        incident_id = request.query_params.get("incident_id", "")

        if not observables:
            raise APIException(
                _(
                    "No observable provided. Please provide one or multiple observable as GET parameter."
                )
            )

        try:
            mp = self.get_mp(request.user)
            # We don't have the artifact type
            # So we search in all types. Can be very slow
            basic_tags = ["fir-incident"]
            if incident_id:
                basic_tags.append(f"fir-{incident_id}")

            results = {"known": [], "unknown": [], "basic_tags": basic_tags}
            for entry in observables:
                for r in mp.searchall(entry):
                    if r["result"]:
                        # we take the last result (the most recent)
                        # We want to know the creator org, the threatlevel, the name + a link (relatedevent) & a date
                        last_res = r["result"][-1]
                        tags = []
                        if "Tag" in last_res.keys():
                            tags = [t["name"] for t in last_res["Tag"]]
                        else:
                            tags = []

                        results["known"].append(
                            {
                                "url": r["url"] + "/events/view/" + str(last_res["id"]),
                                "value": entry,
                                "threat_level": str(last_res["threat_level_id"]),
                                "date": str(last_res["date"]),
                                "info": str(last_res["info"]),
                                "org_name": str(last_res["Orgc"]["name"]),
                                "tags": tags,
                                "basic_tags": [x for x in basic_tags if x not in tags],
                            }
                        )
                    else:
                        results["unknown"].append(
                            {
                                "value": entry,
                                "basic_tags": basic_tags,
                            }
                        )
            # Now we search the related events
            related_events = self.get_misp_related_events(request.user, basic_tags[-1])
            if len(related_events) > 0:
                results["related_events"] = related_events
        except (ValueError, PyMISPError) as e:
            return Response(
                {"error": _("Unable to retrieve content from MISP"), "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return Response(results)

    def create(self, request, *args, **kwargs):
        mp = self.get_mp(request.user)

        try:
            observables = request.data.get("observables", [])
            misp_events = [x["value"] for x in request.data.get("misp_events", [])]
            incident_id = request.data.get("fid", "")

            # Sanity Check
            if not isinstance(incident_id, str) or not incident_id:
                raise ValueError("string expected for fid")

            fir_title = f"{incident_id}".lower()

            for obs in observables:
                misp_observables = []
                tags_for_event = ["fir-incident", fir_title]

                if not isinstance(obs, dict):
                    raise ValueError("list of dict expected for observables")
                if not isinstance(obs.get("tags", False), list):
                    raise ValueError("list expected for tags")
                for tag in obs.get("tags", []):
                    if not isinstance(tag, str):
                        raise ValueError("string expected for each tag")
                    tags_for_event.append(tag)
                if not isinstance(obs.get("value", False), str):
                    raise ValueError("string expected for value")

                misp_observables.append(
                    {"value": obs["value"], "tags": obs["tags"], "type": "other"}
                )

                # If not misp event was supplied: we create a new one
                if not misp_events:
                    misp_events = mp.create_event(f"Event from {fir_title}", tags=[])
                    # No tags: they will be added later

                for event in misp_events:
                    # Add tags fir-incident & id if the event doesn't have them
                    mp.add_tags_to_event(event, list(set(tags_for_event)))
                    mp.add_attributes_to_event(
                        misp_observables, event, comment=f"imported from {fir_title}"
                    )
        except (
            ValueError,
            PyMISPError,
            KeyError,
        ) as e:
            return Response(
                {"error": _("Unable to push content to MISP"), "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"response": "ok"})

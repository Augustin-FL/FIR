import importlib
from django.apps import apps
from rest_framework.exceptions import ParseError
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.db.models import Q
from django.apps import apps
from django_filters.rest_framework import (
    FilterSet,
    DateTimeFilter,
    CharFilter,
    NumberFilter,
    MultipleChoiceFilter,
    BooleanFilter,
    ModelChoiceFilter,
    ModelMultipleChoiceFilter,
    ChoiceFilter,
)

from incidents.models import (
    Incident,
    Label,
    IncidentCategory,
    BusinessLine,
    ValidAttribute,
    Comments,
    File,
    SeverityChoice,
    STATUS_CHOICES,
    CONFIDENTIALITY_LEVEL,
)
from fir_artifacts.models import File, Artifact
from fir_api.lexer import SearchParser
from fir.config.base import INSTALLED_APPS


class BLChoiceFilter(ModelMultipleChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs["method"] = self.filter_bl
        super().__init__(*args, **kwargs)

    def filter_bl(self, queryset, name, value):
        """
        Custom handling to also retrieve children BLs
        """
        bls = []
        for v in value:
            bls.append(v)
            bls.extend(v.get_descendants())
        if bls:
            filter_dict = {name + "__in": [b.name for b in bls]}
            queryset = queryset.filter(**filter_dict)
        return queryset


class ValueChoiceFilter(ChoiceFilter):
    def __init__(self, choices, **kwargs):
        self._choices = choices
        super(ValueChoiceFilter, self).__init__(choices=choices, **kwargs)

    def filter(self, qs, value):
        for choice in self._choices:
            if choice[1] == value:
                return super().filter(qs, choice[0])
        return qs

    @property
    def field(self):
        fields = super().field
        fields.choices = [(b[1], b[1]) for b in self._choices]
        return fields


class IncidentFilter(FilterSet):
    """
    A custom filter class for Incidents filtering
    """

    id = NumberFilter(field_name="id")
    severity = ModelMultipleChoiceFilter(
        to_field_name="name",
        field_name="severity__name",
        queryset=SeverityChoice.objects.all(),
    )
    created_before = DateTimeFilter(field_name="date", lookup_expr="lte")
    created_after = DateTimeFilter(field_name="date", lookup_expr="gte")
    subject = CharFilter(field_name="subject", lookup_expr="icontains")
    description = CharFilter(field_name="description", lookup_expr="icontains")
    status = ValueChoiceFilter(field_name="status", choices=STATUS_CHOICES)
    status__not = ValueChoiceFilter(
        field_name="status",
        choices=STATUS_CHOICES,
        exclude=True,
        label=_("Status is not"),
    )
    confidentiality = ValueChoiceFilter(
        field_name="confidentiality", choices=CONFIDENTIALITY_LEVEL
    )
    is_starred = BooleanFilter(field_name="is_starred")
    concerned_business_lines = BLChoiceFilter(
        to_field_name="name",
        field_name="concerned_business_lines__name",
        queryset=BusinessLine.objects.all(),
    )
    category = ModelMultipleChoiceFilter(
        to_field_name="name",
        field_name="category__name",
        queryset=IncidentCategory.objects.all(),
    )
    detection = ModelChoiceFilter(
        field_name="detection__name",
        to_field_name="name",
        queryset=Label.objects.filter(group__name="detection"),
    )
    is_incident = BooleanFilter(field_name="is_incident")
    is_major = BooleanFilter(field_name="is_major")
    last_comment_date_before = DateTimeFilter(
        field_name="last_comment_date",
        lookup_expr="lte",
        label=_("Last comment date is less than or equal to"),
    )
    last_comment_date_after = DateTimeFilter(
        field_name="last_comment_date",
        lookup_expr="gte",
        label=_("Last comment date is greater than or equal to"),
    )
    query = CharFilter(
        method="search_query", label=_("Custom search query (DSL syntax)")
    )
    attribute = ModelMultipleChoiceFilter(
        to_field_name="name",
        field_name="attribute__name",
        queryset=ValidAttribute.objects.all(),
        label=_("Has attribute"),
    )
    search_filters = []
    keyword_filters = {}

    # BL search: search in selected BL and childrens
    @staticmethod
    def search_bl(x):
        q = Q(concerned_business_lines__name__iexact=x)
        for bl in BusinessLine.objects.filter(name__iexact=x):
            bls = [bl]
            bls.extend(bl.get_descendants())
            q = q | Q(concerned_business_lines__in=bls)
        return q

    def search_query(self, queryset, name, search_query):
        # Build possible fields list
        possible_fields = {}
        for field in queryset.model._meta.fields:
            if str(field.get_internal_type()) in [
                "CharField",
                "TextField",
            ]:
                possible_fields[field.name.lower()] = field.name.lower() + "__icontains"

        # Define custom mapping for specific fields
        possible_fields.update(
            {
                "bl": self.search_bl,
                "plan": "plan__name__iexact",
                "id": lambda x: Q(
                    id=(
                        x.removesuffix(settings.INCIDENT_ID_PREFIX)
                        if settings.INCIDENT_SHOW_ID
                        else x
                    )
                ),
                "starred": lambda x: Q(
                    is_starred=True if x.lower() in ["true", 1, "yes", "y"] else False
                ),
                "opened_by": "opened_by__username__iexact",
                "category": "category__name__icontains",
                "status": "status__iexact",
                "severity": "severity__name__iexact",
            }
        )
        # Custom fields added by plugins
        possible_fields.update(self.keyword_filters)

        # Text entered without "field:"
        # Searching in subject description and comments by default
        default_fields = [
            lambda x: Q(subject__icontains=x)
            | Q(description__icontains=x)
            | Q(comments__comment__icontains=x)
        ]
        # default field added by plugins
        default_fields.extend(self.search_filters)

        try:
            lexer = SearchParser(possible_fields, default_fields, search_query)
            q = lexer.get_q()
        except Exception as e:
            raise ParseError(_(f"Query DSL is not valid: %s" % e))
        return queryset.filter(q)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Reset search_filter to accommodate object reuse
        self.search_filters = []

        # Load Additional incident filters defined in plugins via a hook
        for app in INSTALLED_APPS:
            if app.startswith("fir_"):
                try:
                    h = importlib.import_module(f"{app}.hooks")
                except ImportError:
                    continue

                fields = h.hooks.get("incident_fields", [])
                if isinstance(fields, list):
                    if len(fields) >= 3 and isinstance(fields[3], dict):
                        for k, v in fields[3].items():
                            self.filters.update({k: v})
                fields = h.hooks.get("search_filter", [])
                if isinstance(fields, list):
                    self.search_filters.extend(fields)

                fields = h.hooks.get("keyword_filter", {})
                if isinstance(fields, dict):
                    self.keyword_filters.update(fields)

    class Meta:
        model = Incident
        fields = [
            "id",
            "subject",
            "description",
            "status",
            "concerned_business_lines",
            "severity",
            "category",
            "detection",
            "query",
            "attribute",
        ]


class ArtifactFilter(FilterSet):
    """
    A custom filter class for artifacts filtering
    """

    id = NumberFilter(field_name="id")
    type = CharFilter(field_name="type")
    value = CharFilter(field_name="value", lookup_expr="icontains")
    incidents = NumberFilter(field_name="incidents__id")

    class Meta:
        model = Artifact
        fields = ["id", "type", "incidents", "value"]


class LabelFilter(FilterSet):
    """
    A custom filter class for Label filtering
    """

    id = NumberFilter(field_name="id")
    name = CharFilter(field_name="name")

    class Meta:
        model = Label
        fields = ["id", "name", "group"]


class ValidAttributeFilter(FilterSet):
    id = NumberFilter(field_name="id")
    name = CharFilter(field_name="name")
    unit = NumberFilter(field_name="unit")
    description = CharFilter(field_name="description")
    categories = ModelChoiceFilter(
        to_field_name="name",
        field_name="categories__name",
        queryset=IncidentCategory.objects.all(),
    )


class CategoryFilter(FilterSet):
    """
    Custom filtering for incidents categories
    """

    id = NumberFilter(field_name="id")
    name = CharFilter(field_name="name")
    is_major = BooleanFilter(field_name="is_major")


class SeverityFilter(FilterSet):
    """
    Custom filtering for incidents severities
    """

    name = CharFilter(field_name="name")
    color = CharFilter(field_name="color")


class AttributeFilter(FilterSet):
    id = NumberFilter(field_name="id")
    name = CharFilter(field_name="name")
    value = CharFilter(field_name="value", lookup_expr="icontains")
    incident = NumberFilter(field_name="incident")


class FileFilter(FilterSet):
    """
    Custom filtering so we can partially match on name
    """

    id = NumberFilter(field_name="id")
    description = CharFilter(field_name="description", lookup_expr="icontains")
    uploaded_before = DateTimeFilter(field_name="date", lookup_expr="lte")
    uploaded_after = DateTimeFilter(field_name="date", lookup_expr="gte")
    incident = NumberFilter(field_name="incident__id")

    class Meta:
        model = File
        fields = ["id", "description", "incident"]


class BLFilter(FilterSet):
    """
    Custom filtering class for BL Filtering
    """

    id = NumberFilter(field_name="id")
    name = BLChoiceFilter(
        to_field_name="name",
        field_name="name",
        queryset=BusinessLine.objects.all(),
    )


class CommentFilter(FilterSet):
    """
    A custom filter class for Comment filtering
    """

    id = NumberFilter(field_name="id")
    created_before = DateTimeFilter(field_name="date", lookup_expr="lte")
    created_after = DateTimeFilter(field_name="date", lookup_expr="gte")
    opened_by = CharFilter(field_name="opened_by__username")
    action = ModelChoiceFilter(
        to_field_name="name",
        field_name="action__name",
        queryset=Label.objects.filter(group__name="action"),
    )
    incident = NumberFilter(field_name="incident__id")

    class Meta:
        model = Comments
        fields = ["id", "date", "incident", "opened_by", "action"]


class StatsFilter(IncidentFilter):
    aggregation = CharFilter(method="aggregate_by", label=_("Aggregate by"))
    unit = CharFilter(method="set_unit", label=_("Perform stats on"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for k in self.filters:
            # Disable distinct count for MultipleChoiceFilter
            if isinstance(
                self.filters[k], (ModelMultipleChoiceFilter, MultipleChoiceFilter)
            ):
                self.filters[k].distinct = False

    def set_unit(self, queryset, name, unit):
        valid_unit = ["attribute", "incident"]

        if unit not in valid_unit:
            raise ParseError(_(f"'{unit}' is not part of {valid_unit}"))

        return queryset

    def aggregate_by(self, queryset, name, aggregate_by):
        valid_aggregations = [
            "category",
            "severity",
            "entity",
            "detection",
            "actor",
            "date",
            "baselcategory",
        ]

        for elem in aggregate_by.split(","):
            if elem not in valid_aggregations:
                raise ParseError(_(f"'{elem}' is not part of {valid_aggregations}"))

        return queryset

    class Meta:
        model = Incident
        fields = [
            "id",
            "subject",
            "description",
            "status",
            "concerned_business_lines",
            "severity",
            "category",
            "detection",
            "query",
            "unit",
            "aggregation",
        ]
